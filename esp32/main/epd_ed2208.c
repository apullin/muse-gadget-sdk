/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// M5Stack M5Paper Color: 4 inch 400x600 E Ink Spectra 6 (EL040EF1, ED2208
// controller), six colours, 4 bits per pixel, full refreshes only. The panel
// and the microSD slot share SPI2; the M5PM1 power chip switches both on.
//
// Controller commands and power-up: M5Stack's M5GFX (Panel_ED2208,
// board_M5PaperColor; github.com/m5stack/M5GFX) and M5PaperColor-UserDemo.

#include "epd_panel.h"

#include <string.h>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "driver/spi_master.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "link.led";

#define EPD_HOST        SPI2_HOST
#define EPD_PIN_SCLK    15
#define EPD_PIN_MOSI    13
#define EPD_PIN_CS      44
#define EPD_PIN_DC      43
#define EPD_PIN_RST     12
#define EPD_PIN_BUSY    11
#define SD_PIN_CS       47
#define EPD_SPI_HZ      (4 * 1000 * 1000)
#define EPD_W           400
#define EPD_H           600
#define EPD_ROW_BYTES   (EPD_W / 2)
#define EPD_FRAME_BYTES (EPD_ROW_BYTES * EPD_H)
#define EPD_CHUNK_BYTES 4000
#define EPD_BUSY_TIMEOUT_MS 60000

#define PM1_I2C_PORT    I2C_NUM_0
#define PM1_PIN_SDA     3
#define PM1_PIN_SCL     2
#define PM1_ADDR        0x6E
#define PM1_GPIO_EPD    (1 << 0)
#define PM1_GPIO_SD     (1 << 3)

static spi_device_handle_t s_spi;
static uint8_t *s_chunk;

// ---- M5PM1 ------------------------------------------------------------------

static esp_err_t pm1_read(i2c_master_dev_handle_t dev, uint8_t reg, uint8_t *val) {
    return i2c_master_transmit_receive(dev, &reg, 1, val, 1, 100);
}

static esp_err_t pm1_write(i2c_master_dev_handle_t dev, uint8_t reg, uint8_t val) {
    const uint8_t buf[2] = {reg, val};
    return i2c_master_transmit(dev, buf, sizeof(buf), 100);
}

static esp_err_t pm1_update(i2c_master_dev_handle_t dev, uint8_t reg, uint8_t clear, uint8_t set) {
    uint8_t val;
    esp_err_t err = pm1_read(dev, reg, &val);
    if (err == ESP_OK) err = pm1_write(dev, reg, (uint8_t)((val & ~clear) | set));
    return err;
}

// Drives the M5PM1's GPIO0 (panel power) and GPIO3 (microSD power) high, so
// the card can't load the shared SPI lines either.
static esp_err_t pm1_power_on(void) {
    i2c_master_bus_handle_t bus = NULL;
    esp_err_t err = i2c_master_get_bus_handle(PM1_I2C_PORT, &bus);
    if (err != ESP_OK) {
        const i2c_master_bus_config_t bus_cfg = {
            .i2c_port = PM1_I2C_PORT,
            .sda_io_num = PM1_PIN_SDA,
            .scl_io_num = PM1_PIN_SCL,
            .clk_source = I2C_CLK_SRC_DEFAULT,
            .glitch_ignore_cnt = 7,
            .flags.enable_internal_pullup = true,
        };
        err = i2c_new_master_bus(&bus_cfg, &bus);
        // The M5PM1 keeps power across ESP32 resets, so a reset mid-transfer
        // can leave it holding SDA low; clock it free (as M5Stack's demo does).
        if (err == ESP_OK && esp_reset_reason() != ESP_RST_POWERON) i2c_master_bus_reset(bus);
    }
    const i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = PM1_ADDR,
        .scl_speed_hz = 100000,
    };
    i2c_master_dev_handle_t dev = NULL;
    if (err == ESP_OK) err = i2c_master_bus_add_device(bus, &dev_cfg, &dev);
    // The M5PM1 may be in I2C idle sleep, which a first transfer wakes.
    uint8_t probe;
    if (err == ESP_OK && pm1_read(dev, 0x09, &probe) != ESP_OK) vTaskDelay(pdMS_TO_TICKS(10));
    // 0x0A: watchdog count, 0 turns the PMIC's watchdog off.
    if (err == ESP_OK) err = pm1_write(dev, 0x0A, 0x00);
    // 0x16: pin functions, two bits per pin; 00 is plain GPIO.
    if (err == ESP_OK) err = pm1_update(dev, 0x16, 0x03 << 0 | 0x03 << 6, 0);
    // 0x10: outputs. 0x13: push-pull. 0x11: driven high.
    if (err == ESP_OK) err = pm1_update(dev, 0x10, 0, PM1_GPIO_EPD | PM1_GPIO_SD);
    if (err == ESP_OK) err = pm1_update(dev, 0x13, PM1_GPIO_EPD | PM1_GPIO_SD, 0);
    if (err == ESP_OK) err = pm1_update(dev, 0x11, 0, PM1_GPIO_EPD | PM1_GPIO_SD);
    // 0x09: no I2C idle sleep. The PMIC stays powered on battery across
    // ESP32 resets, so whatever ran before may have left it set.
    if (err == ESP_OK) err = pm1_write(dev, 0x09, 0x00);
    if (dev) i2c_master_bus_rm_device(dev);
    if (err == ESP_OK) vTaskDelay(pdMS_TO_TICKS(100));
    return err;
}

// ---- ED2208 -----------------------------------------------------------------

static esp_err_t epd_write(bool data, const uint8_t *buf, size_t len) {
    gpio_set_level(EPD_PIN_DC, data);
    while (len) {
        size_t n = len < EPD_CHUNK_BYTES ? len : EPD_CHUNK_BYTES;
        memcpy(s_chunk, buf, n);
        spi_transaction_t t = {.length = n * 8, .tx_buffer = s_chunk};
        esp_err_t err = spi_device_polling_transmit(s_spi, &t);
        if (err != ESP_OK) return err;
        buf += n;
        len -= n;
    }
    return ESP_OK;
}

static esp_err_t epd_cmd(uint8_t cmd, const uint8_t *data, size_t len) {
    esp_err_t err = epd_write(false, &cmd, 1);
    if (err == ESP_OK && len) err = epd_write(true, data, len);
    return err;
}

static esp_err_t epd_wait_idle(void) {
    int64_t give_up = esp_timer_get_time() + EPD_BUSY_TIMEOUT_MS * 1000LL;
    while (gpio_get_level(EPD_PIN_BUSY) == 0) {
        if (esp_timer_get_time() > give_up) return ESP_ERR_TIMEOUT;
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    return ESP_OK;
}

typedef struct { uint8_t cmd, len; uint8_t data[6]; } init_cmd_t;

// The EL040EF1's values, which differ from the reTerminal E1002 panel's.
static const init_cmd_t s_init[] = {
    {0xAA, 6, {0x49, 0x55, 0x20, 0x08, 0x09, 0x18}},
    {0x01, 1, {0x3F}},
    {0x00, 2, {0x5F, 0x69}},
    {0x05, 4, {0x40, 0x1F, 0x1F, 0x2C}},
    {0x08, 4, {0x6F, 0x1F, 0x1F, 0x22}},
    {0x06, 4, {0x6F, 0x1F, 0x17, 0x17}},
    {0x03, 4, {0x03, 0x54, 0x00, 0x44}},
    {0x60, 2, {0x02, 0x00}},
    {0x30, 1, {0x08}},
    {0x50, 1, {0x3F}},
    {0xE3, 1, {0x2F}},
    {0x84, 1, {0x01}},
};

static esp_err_t ed2208_init(void) {
    const gpio_config_t out = {
        .pin_bit_mask = 1ULL << EPD_PIN_DC | 1ULL << EPD_PIN_RST | 1ULL << SD_PIN_CS,
        .mode = GPIO_MODE_OUTPUT,
    };
    const gpio_config_t busy = {
        .pin_bit_mask = 1ULL << EPD_PIN_BUSY,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    esp_err_t err = gpio_config(&out);
    if (err == ESP_OK) err = gpio_config(&busy);
    gpio_set_level(EPD_PIN_RST, 1);
    gpio_set_level(SD_PIN_CS, 1);  // keep the microSD card off the bus
    if (err == ESP_OK) err = pm1_power_on();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "M5PM1 panel power: %s", esp_err_to_name(err));
        return err;
    }
    const spi_bus_config_t bus = {
        .sclk_io_num = EPD_PIN_SCLK,
        .mosi_io_num = EPD_PIN_MOSI,
        .miso_io_num = -1,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = EPD_CHUNK_BYTES,
    };
    const spi_device_interface_config_t dev = {
        .mode = 0,
        .clock_speed_hz = EPD_SPI_HZ,
        .spics_io_num = EPD_PIN_CS,
        .queue_size = 1,
    };
    s_chunk = heap_caps_malloc(EPD_CHUNK_BYTES, MALLOC_CAP_DMA);
    if (!s_chunk) return ESP_ERR_NO_MEM;
    err = spi_bus_initialize(EPD_HOST, &bus, SPI_DMA_CH_AUTO);
    if (err == ESP_OK) err = spi_bus_add_device(EPD_HOST, &dev, &s_spi);
    return err;
}

static esp_err_t ed2208_update(const uint8_t *frame, const uint8_t *prev, bool full) {
    (void)prev;
    (void)full;
    gpio_set_level(EPD_PIN_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(EPD_PIN_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
    esp_err_t err = epd_wait_idle();
    for (size_t i = 0; err == ESP_OK && i < sizeof(s_init) / sizeof(s_init[0]); i++) {
        err = epd_cmd(s_init[i].cmd, s_init[i].data, s_init[i].len);
    }
    static const uint8_t resolution[] = {EPD_W >> 8, EPD_W & 0xFF, EPD_H >> 8, EPD_H & 0xFF};
    if (err == ESP_OK) err = epd_wait_idle();
    if (err == ESP_OK) err = epd_cmd(0x61, resolution, sizeof(resolution));
    static const uint8_t zero = 0x00;
    if (err == ESP_OK) err = epd_cmd(0x10, frame, EPD_FRAME_BYTES);
    if (err == ESP_OK) err = epd_wait_idle();
    if (err == ESP_OK) err = epd_cmd(0x04, NULL, 0);
    if (err == ESP_OK) err = epd_wait_idle();
    vTaskDelay(pdMS_TO_TICKS(200));
    // Booster soft start for the refresh, as M5GFX sends it.
    static const uint8_t booster[] = {0x6F, 0x1F, 0x17, 0x27};
    if (err == ESP_OK) err = epd_cmd(0x06, booster, sizeof(booster));
    vTaskDelay(pdMS_TO_TICKS(200));
    int64_t start = esp_timer_get_time();
    if (err == ESP_OK) err = epd_cmd(0x12, &zero, 1);
    if (err == ESP_OK) err = epd_wait_idle();
    int ms = (int)((esp_timer_get_time() - start) / 1000);
    if (err == ESP_OK) err = epd_cmd(0x02, &zero, 1);
    if (err == ESP_OK) err = epd_wait_idle();
    static const uint8_t check = 0xA5;
    if (err == ESP_OK) err = epd_cmd(0x07, &check, 1);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "e-paper refresh failed: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "e-paper full refresh in %d ms", ms);
    return ESP_OK;
}

static const epd_panel_t s_panel = {
    .name            = "M5Paper Color Spectra 6",
    .depth           = "6 colours, 4 bits per pixel",
    .width           = EPD_W,
    .height          = EPD_H,
    .bits_per_pixel  = 4,
    .title_y         = 48,
    .title_max_scale = 5,
    .anim_scale      = 4,
    .anim_y          = 150,
    .status_y        = 480,
    .status_scale    = 3,
    .init            = ed2208_init,
    .update          = ed2208_update,
};

const epd_panel_t *epd_panel_get(void) { return &s_panel; }
