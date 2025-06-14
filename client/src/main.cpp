#include <M5Unified.h>
#include <MAX30100.h>
#include <math.h>
#include <vector>
#include <cstring>
#include "agrasta.h"
#include <WiFi.h>
#include <PubSubClient.h>

using namespace AGRASTA;

// Wi-Fi credentials
const char *ssid = "Stofa71747_2.4GHz";
const char *password = "";

// MQTT Broker IP and port
const char *mqtt_server = "192.168.87.199";
const int mqtt_port = 1883;

WiFiClient espClient;
PubSubClient client(espClient);

// --- Constants & Globals ---
static const int WAVE_FORM_SIZE = 1000;
static const int FILTER_SIZE = 5;
const size_t AGRASTA_BLOCK_SIZE_BYTES = 17;
const size_t AGRASTA_BLOCK_SIZE_BITS = 128;

// --- Normal Range Definitions ---
const float NORMAL_BPM_MIN = 50.0;
const float NORMAL_BPM_MAX = 100.0;
const float NORMAL_SPO2_MIN = 75.0;

// --- Batch Size ---
const int RESULTS_PER_ENCRYPTION_BATCH = AGRASTA_BLOCK_SIZE_BYTES;
const int COLLECTION_BUFFER_SIZE = RESULTS_PER_ENCRYPTION_BATCH;

// Define Port A pins explicitly for clarity
const int I2C_SDA_PIN_PORTA = 32;
const int I2C_SCL_PIN_PORTA = 33;
// Define Default ESP32 I2C pins explicitly for clarity
const int I2C_SDA_PIN_DEFAULT = 21;
const int I2C_SCL_PIN_DEFAULT = 22;

// Buffers
uint32_t irBuffer[WAVE_FORM_SIZE] = {0};
uint32_t redBuffer[WAVE_FORM_SIZE] = {0};
uint32_t filterIR[FILTER_SIZE] = {0};
uint32_t filterRed[FILTER_SIZE] = {0};

int bufferIndex = 0;
unsigned long lastBeat = 0; // Time of the last detected heartbeat pulse
unsigned long lastSpO2Calc = 0;
const unsigned long SPO2_CALC_INTERVAL_MS = 2000; // Calculate SpO2 every 2 seconds

// Main measurement results
float bpm = 0;
float spo2 = 0;

// Battery monitoring
float batteryLevel = 0;
unsigned long lastBatteryCheck = 0;
const unsigned long BATTERY_CHECK_INTERVAL_MS = 10000; // Check battery every 10 seconds

// Sensor object
MAX30100 particleSensor;
bool bufferIsFull = false; // Flag for main data buffer
bool fingerPresent = false;
uint32_t lastAvgIR = 0;  // Store last average IR for display
uint32_t lastAvgRed = 0; // Store last average Red for display

// --- Data Collection & Encryption Variables ---
std::vector<uint8_t> result_collection_buffer;
int result_collection_count = 0;
std::vector<uint8_t> encryptionKey = {
    0x0c, 0x7c, 0xc2, 0x27, 0xec, 0xed, 0x1e, 0x4f,
    0x33, 0xdb, 0xe4, 0xab, 0xdd, 0xfb, 0xb3, 0xbd, 0x80};

AGRASTA_128 *cipher = nullptr;

// --- BPM State Variables (File Scope) ---
// Declared ONCE here as static file-scope variables.
static float lastBPM = 0;          // Stores the smoothed BPM value between calculations
static bool initialized = false;   // Tracks if BPM calculation has been initialized
static uint32_t history[10] = {0}; // Buffer for initial IR values for thresholding
static int historyIndex = 0;       // Index for the history buffer
static bool rising = false;        // Tracks if the signal is currently rising (peak detection)
// 'threshold' will be a local static inside updateBPM

// --- Display Sprite ---
M5Canvas canvas(&M5.Display); // Create a Canvas (sprite) associated with the display

// --- Helper Functions ---

// Wi-Fi and MQTT setup
void setup_wifi()
{
  WiFi.begin(ssid, password);
  Serial.print("Connecting to Wi-Fi");
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWi-Fi connected.");
}

void mqtt_reconnect()
{
  while (!client.connected())
  {
    Serial.print("Attempting MQTT connection...");
    if (client.connect("M5Core2Client"))
    {
      Serial.println("connected");
    }
    else
    {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" retrying in 5s");
      delay(5000);
    }
  }
}

String bytesToHex(const std::vector<uint8_t> &data)
{
  String hexString;
  hexString.reserve(data.size() * 2);
  for (auto b : data)
  {
    if (b < 0x10)
      hexString += "0";
    hexString += String(b, HEX);
  }
  return hexString;
}
void drawBatteryBar(M5Canvas *targetCanvas, int x, int y, int w, int h, float level)
{
  targetCanvas->drawRoundRect(x, y, w, h, 3, TFT_WHITE);
  int innerWidth = (int)((w - 4) * (level / 100.0));
  if (innerWidth < 0)
    innerWidth = 0;
  if (innerWidth > w - 4)
    innerWidth = w - 4;
  uint16_t barColor = TFT_GREEN;
  if (level < 20)
    barColor = TFT_RED;
  else if (level < 50)
    barColor = TFT_YELLOW;
  targetCanvas->fillRect(x + 2, y + 2, w - 4, h - 4, TFT_BLACK); // Background inside border
  targetCanvas->fillRoundRect(x + 2, y + 2, innerWidth, h - 4, 2, barColor);
}

uint32_t averageArray(uint32_t *arr, int size)
{
  if (size <= 0)
    return 0;
  uint64_t sum = 0;
  for (int i = 0; i < size; i++)
    sum += arr[i];
  return (uint32_t)(sum / size);
}

// --- BPM Update Function ---
// Uses the file-scoped static variables: initialized, history, historyIndex, rising, lastBPM
// Uses the global variable: lastBeat, bpm
void updateBPM(uint32_t irValue)
{
  // Threshold for peak detection - local static is fine here
  static float threshold = 0;

  // Constants for BPM calculation
  const unsigned long MIN_BEAT_INTERVAL_MS = 300;  // Corresponds to 200 BPM max
  const unsigned long MAX_BEAT_INTERVAL_MS = 2000; // Corresponds to 30 BPM min
  const float ALPHA = 0.025f;                      // Rate of threshold adjustment
  const float BETA = 0.3f;                         // Smoothing factor for BPM

  // Initialization phase: calculate baseline threshold
  if (!initialized) // Use file-scoped 'initialized'
  {
    if (irValue < 1000)
      return;                          // Wait for a stronger signal to initialize
    history[historyIndex++] = irValue; // Use file-scoped 'history' and 'historyIndex'
    if (historyIndex < 10)
      return; // Need 10 samples

    uint64_t sum = 0;
    for (int i = 0; i < 10; ++i)
      sum += history[i];
    threshold = (sum > 0) ? (float)(sum / 10.0f) : 8000; // Initial threshold guess
    initialized = true;                                  // Use file-scoped 'initialized'
    lastBeat = millis();                                 // Reset beat timer (global variable)
    Serial.printf("BPM Initialized. Initial Threshold: %.1f\n", threshold);
    return;
  }

  // Dynamically adjust threshold based on recent IR values
  threshold = (1.0f - ALPHA) * threshold + ALPHA * (float)irValue;

  // Detect rising edge (potential heartbeat peak)
  if (irValue > threshold && !rising) // Use file-scoped 'rising'
  {
    rising = true; // Use file-scoped 'rising'
    unsigned long now = millis();
    unsigned long beatInterval = now - lastBeat; // Use global 'lastBeat'

    // Check if the interval is within a plausible range for a heartbeat
    if (beatInterval > MIN_BEAT_INTERVAL_MS && beatInterval < MAX_BEAT_INTERVAL_MS)
    {
      if (lastBeat != 0) // Avoid calculation on the very first beat after init
      {
        float newBPM = 60000.0f / beatInterval;
        // Apply exponential smoothing to the BPM reading
        lastBPM = (lastBPM == 0) ? newBPM : (1.0f - BETA) * lastBPM + BETA * newBPM; // Use file-scoped 'lastBPM'
        bpm = lastBPM;                                                               // Update the global 'bpm' variable for display/use
      }
      lastBeat = now; // Record the time of this valid beat
    }
    else if (beatInterval >= MAX_BEAT_INTERVAL_MS)
    {
      // Interval too long, likely missed beat or finger movement. Reset lastBeat timer.
      lastBeat = now;
    }
    // If interval is too short, likely noise, ignore it and wait for the next rising edge.
  }
  // Detect falling edge (signal dropped below threshold after a peak)
  else if (irValue < threshold && rising) // Use file-scoped 'rising'
  {
    rising = false; // Use file-scoped 'rising'
  }

  // Timeout: If no valid beat detected for a long time, reset BPM calculation state
  if (initialized && (millis() - lastBeat > MAX_BEAT_INTERVAL_MS * 2.5))
  {
    if (bpm != 0) // Only reset and print if BPM was previously non-zero
    {
      Serial.println("BPM Timeout - Resetting BPM calculation.");
      bpm = 0; // Reset global display BPM
      // Reset file-scoped state variables
      lastBPM = 0;
      initialized = false;
      historyIndex = 0;
      rising = false;
    }
  }
}

// --- Battery Update Function ---
void updateBattery()
{
  if (millis() - lastBatteryCheck > BATTERY_CHECK_INTERVAL_MS)
  {
    batteryLevel = M5.Power.getBatteryLevel();
    lastBatteryCheck = millis();
  }
}

// --- SpO2 Calculation Function ---
// (Added robustness checks)
float calculateSpO2(uint32_t *irData, uint32_t *redData, int bufferLength)
{
  if (bufferLength < 50)
    return 0; // Need sufficient data

  double sumIr = 0, sumRed = 0;
  uint32_t minIR = 0xFFFFFFFF, maxIR = 0; // Initialize min high, max low
  uint32_t minRed = 0xFFFFFFFF, maxRed = 0;
  int validPoints = 0; // Count valid data points

  // First pass: Calculate DC levels and find min/max, skipping invalid points
  for (int i = 0; i < bufferLength; i++)
  {
    // Skip potentially invalid zero or saturated readings
    if (irData[i] < 100 || redData[i] < 100 || irData[i] >= 65530 || redData[i] >= 65530)
    {
      continue; // Skip this data point
    }
    validPoints++;
    sumIr += irData[i];
    sumRed += redData[i];
    if (irData[i] < minIR)
      minIR = irData[i];
    if (irData[i] > maxIR)
      maxIR = irData[i];
    if (redData[i] < minRed)
      minRed = redData[i];
    if (redData[i] > maxRed)
      maxRed = redData[i];
  }

  if (validPoints < 50)
    return 0; // Need enough valid points

  double dcIr = sumIr / validPoints;
  double dcRed = sumRed / validPoints;

  // Basic signal quality checks
  const uint32_t MIN_DC_LEVEL = 1000;    // Minimum average signal strength
  const uint32_t MIN_SIGNAL_RANGE = 200; // Minimum peak-to-peak variation
  if (dcIr < MIN_DC_LEVEL || dcRed < MIN_DC_LEVEL)
    return 0; // Signal too weak
  if (maxIR <= minIR || maxRed <= minRed)
    return 0; // Should not happen if validPoints > 0
  if ((maxIR - minIR < MIN_SIGNAL_RANGE) || (maxRed - minRed < MIN_SIGNAL_RANGE))
    return 0; // Signal too flat (no pulse)

  // Second pass: Calculate AC components (RMS) using valid points only
  double acIrSqSum = 0, acRedSqSum = 0;
  for (int i = 0; i < bufferLength; i++)
  {
    // Skip invalid points again
    if (irData[i] < 100 || redData[i] < 100 || irData[i] >= 65530 || redData[i] >= 65530)
    {
      continue;
    }
    double irDiff = (double)irData[i] - dcIr;
    double redDiff = (double)redData[i] - dcRed;
    acIrSqSum += irDiff * irDiff;
    acRedSqSum += redDiff * redDiff;
  }

  double acIr = sqrt(acIrSqSum / validPoints);
  double acRed = sqrt(acRedSqSum / validPoints);

  const double MIN_AC_RMS_LEVEL = 50; // Minimum pulsatile component strength
  if (acIr < MIN_AC_RMS_LEVEL || acRed < MIN_AC_RMS_LEVEL)
    return 0; // Pulse signal too weak

  // Avoid division by zero
  if (dcIr == 0 || dcRed == 0 || acIr == 0)
    return 0;

  // Calculate R ratio
  double R = (acRed / dcRed) / (acIr / dcIr);

  // Standard SpO2 formula (adjust coefficients if needed based on calibration)
  double calculatedSpO2 = 110.0 - 25.0 * R;

  // Clamp result to plausible physiological range
  if (calculatedSpO2 > 100.0)
    calculatedSpO2 = 100.0;
  else if (calculatedSpO2 < 70.0)
    calculatedSpO2 = 70.0; // Lower bound

  return calculatedSpO2;
}

// ---------------------------------------
// Setup Function
// ---------------------------------------
void setup()
{
  // --- Serial, M5Init, Sprite Setup ---
  Serial.begin(115200);
  delay(500);
  Serial.println("\n\nM5Stack Core2 HR & SpO2 Monitor (MAX30100 + AGRASTA) - Status Bit Encryption");
  Serial.println("----------------------------------------------------");
  auto cfg = M5.config();
  M5.begin(cfg);
  Serial.println("M5 Initialized.");
  Serial.printf("Display: %d x %d\n", M5.Display.width(), M5.Display.height());
  Serial.println("Creating display sprite buffer...");
  canvas.setColorDepth(16);
  if (!canvas.createSprite(M5.Display.width(), M5.Display.height()))
  {
    Serial.println("FATAL ERROR: Failed to create sprite buffer! Halting.");
    M5.Display.fillScreen(TFT_RED); // Use M5.Display directly before canvas is ready
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setFont(&fonts::Font2);
    M5.Display.setCursor(10, 10);
    M5.Display.println("Sprite Error!");
    while (1)
      delay(100);
  }
  else
  {
    Serial.printf(" - Sprite created (%d x %d, %d bpp).\n", canvas.width(), canvas.height(), canvas.getColorDepth());
  }
  canvas.setTextWrap(false); // Prevent text wrapping on the canvas

  // --- I2C Scan ---
  byte error;
  bool device_found = false;
  const byte SENSOR_ADDR = MAX30100_I2C_ADDRESS;
  int sda_pin = I2C_SDA_PIN_PORTA;
  int scl_pin = I2C_SCL_PIN_PORTA;
  Serial.printf("\nAttempting I2C on Port A (SDA: %d, SCL: %d)...\n", sda_pin, scl_pin);
  Wire.begin(sda_pin, scl_pin); // Try Port A first
  delay(100);
  Wire.beginTransmission(SENSOR_ADDR);
  error = Wire.endTransmission();
  if (error != 0) // Device not found on Port A
  {
    Serial.printf("Device NOT found on Port A (Error: %d). Trying default pins...\n", error);
    Wire.end(); // Release Port A pins
    delay(100);
    sda_pin = I2C_SDA_PIN_DEFAULT; // Switch to default pins
    scl_pin = I2C_SCL_PIN_DEFAULT;
    Serial.printf("Attempting I2C on Default Pins (SDA: %d, SCL: %d)...\n", sda_pin, scl_pin);
    Wire.begin(sda_pin, scl_pin); // Initialize with default pins
    delay(100);
    Wire.beginTransmission(SENSOR_ADDR);
    error = Wire.endTransmission();
  }
  // Check result after trying both ports
  if (error == 0)
  {
    Serial.printf("Device found at 0x%02X using pins SDA=%d, SCL=%d. OK.\n", SENSOR_ADDR, sda_pin, scl_pin);
    device_found = true;
    // Optional: Indicate if default pins were needed
    if (sda_pin == I2C_SDA_PIN_DEFAULT)
    {
      canvas.fillSprite(TFT_YELLOW); // Temporary message on screen
      canvas.setTextColor(TFT_BLACK);
      canvas.setFont(&fonts::Font2);
      canvas.setCursor(10, 10);
      canvas.printf("Using I2C G%d/G%d", sda_pin, scl_pin);
      canvas.pushSprite(0, 0);
      delay(1500);
    }
  }
  else
  {
    Serial.printf("Device NOT found on default pins either (Error: %d).\n", error);
  }

  // Halt if device not found
  if (!device_found)
  {
    Serial.println("\nFATAL ERROR: MAX30100 sensor not found. Halting.");
    canvas.fillSprite(TFT_RED);
    canvas.setTextColor(TFT_WHITE);
    canvas.setFont(&fonts::Font2);
    canvas.setCursor(10, 10);
    canvas.println("I2C Scan Failed!");
    canvas.setCursor(10, 40);
    canvas.printf("Addr 0x%02X not found", SENSOR_ADDR);
    canvas.setCursor(10, 70);
    canvas.println("Check Wiring/Power");
    canvas.pushSprite(0, 0);
    while (1)
      delay(100);
  }

  // --- MAX30100 Init & Config ---
  Serial.println("\nInitializing MAX30100 sensor...");
  if (!particleSensor.begin())
  { // Pass Wire reference if needed by library version
    Serial.println("ERROR: MAX30100 sensor begin() failed! Halting.");
    canvas.fillSprite(TFT_RED);
    canvas.setTextColor(TFT_WHITE);
    canvas.setFont(&fonts::Font2);
    canvas.setCursor(10, 10);
    canvas.println("Sensor Init Failed");
    canvas.pushSprite(0, 0);
    while (1)
      delay(100);
  }
  Serial.println("MAX30100 begin() successful.");
  Serial.println("Configuring MAX30100 sensor settings...");
  particleSensor.setMode(MAX30100_MODE_SPO2_HR);
  particleSensor.setLedsPulseWidth(MAX30100_SPC_PW_1600US_16BITS); // Max resolution
  particleSensor.setSamplingRate(MAX30100_SAMPRATE_100HZ);         // 100 samples/sec
                                                                   // Start with moderate current, adjust based on signal strength if needed
  particleSensor.setLedsCurrent(MAX30100_LED_CURR_24MA, MAX30100_LED_CURR_27_1MA);
  particleSensor.setHighresModeEnabled(true); // Enable high-res mode

  // Check Part ID
  uint8_t partId = particleSensor.getPartId();

  Serial.printf(" - Part ID Read: 0x%02X (Expected: 0x%02X)\n", partId, EXPECTED_PART_ID);
  if (partId != EXPECTED_PART_ID)
    Serial.println(" WARNING: Part ID mismatch!");
  else
    Serial.println(" - Part ID matches expected value.");
  particleSensor.resetFifo(); // Clear any stale data in sensor FIFO
  Serial.println(" - FIFO Reset.");

  // --- AGRASTA Init ---
  Serial.println("\nInitializing AGRASTA cipher...");
  if (encryptionKey.size() == 17)
  { // AGRASTA expects 128-bit key + 1 tweak byte
    cipher = new AGRASTA_128(encryptionKey);
    if (cipher)
    {
      Serial.println(" - AGRASTA cipher initialized successfully.");
    }
    else
    {
      Serial.println(" - ERROR: Failed to allocate AGRASTA cipher! Encryption disabled.");
      // Handle memory allocation failure (e.g., display error, halt)
      canvas.fillSprite(TFT_ORANGE);
      canvas.setTextColor(TFT_BLACK);
      canvas.setFont(&fonts::Font2);
      canvas.setCursor(10, 10);
      canvas.println("AGRASTA Alloc Fail!");
      canvas.pushSprite(0, 0);
      delay(3000);
    }
  }
  else
  {
    Serial.printf(" - ERROR: Invalid encryption key size (%d bytes). Expected 17. Encryption disabled.\n", encryptionKey.size());
    // Handle invalid key size (e.g., display error, proceed without encryption)
    canvas.fillSprite(TFT_ORANGE);
    canvas.setTextColor(TFT_BLACK);
    canvas.setFont(&fonts::Font2);
    canvas.setCursor(10, 10);
    canvas.println("Invalid Key Size!");
    canvas.pushSprite(0, 0);
    delay(3000);
  }

  // --- Initialize Collection Buffer ---
  Serial.println("Initializing result collection buffer...");
  result_collection_buffer.reserve(COLLECTION_BUFFER_SIZE); // Reserve 16 bytes
  result_collection_count = 0;                              // Start count at zero

  Serial.println("\nSetup complete. Starting main loop...");
  Serial.println("----------------------------------------------------\n");
  canvas.fillSprite(TFT_BLACK); // Clear screen before starting loop
  canvas.pushSprite(0, 0);
} // End of setup()

// ---------------------------------------
// Main Loop
// ---------------------------------------
void loop()
{
  M5.update();     // Update button states, etc.
  updateBattery(); // Check battery periodically

  // --- Sensor Reading ---
  particleSensor.update(); // Check sensor FIFO for new data
  uint16_t irValue = 0;
  uint16_t redValue = 0;
  // Attempt to get one sample from the FIFO
  bool newData = particleSensor.getRawValues(&irValue, &redValue);

  // --- Data Processing & Finger Detection ---
  const uint32_t FINGER_DETECT_THRESHOLD = 1500;  // IR level threshold
  static unsigned long lastFingerPresentTime = 0; // Track when finger was last reliably detected
  static unsigned long lastFingerCheckTime = 0;   // Throttle finger presence checks
  bool currentFingerPresent = false;              // Status in this specific loop iteration
  bool validDataAvailable = false;                // Flag if BPM/SpO2 seem plausible this iteration

  if (newData) // Process only if new data arrived from sensor
  {
    // Apply simple moving average filter to raw data
    int filter_idx = bufferIndex % FILTER_SIZE;
    filterIR[filter_idx] = irValue;
    filterRed[filter_idx] = redValue;
    lastAvgIR = averageArray(filterIR, FILTER_SIZE);
    lastAvgRed = averageArray(filterRed, FILTER_SIZE);

    // --- Finger Presence Logic ---
    // Check periodically to decide if a finger is present based on average IR
    if (millis() - lastFingerCheckTime > 50) // Check every 50ms
    {
      // Finger likely present if average IR is above threshold AND raw IR isn't near zero
      currentFingerPresent = (lastAvgIR > FINGER_DETECT_THRESHOLD && irValue > 500);
      lastFingerCheckTime = millis();

      if (currentFingerPresent)
      {
        if (!fingerPresent)
        { // Finger JUST placed
          Serial.println("Finger Detected - Resetting buffers and calculations.");
          fingerPresent = true;
          bufferIndex = 0;      // Reset main buffer index
          bufferIsFull = false; // Main buffer needs filling
          bpm = 0;              // Reset display value
          spo2 = 0;             // Reset display value
          // --- RESET BPM State (File-scoped variables) ---
          lastBPM = 0;
          initialized = false;
          historyIndex = 0;
          rising = false;
          // --- Clear sensor data buffers ---
          memset(irBuffer, 0, sizeof(irBuffer));
          memset(redBuffer, 0, sizeof(redBuffer));
          memset(filterIR, 0, sizeof(filterIR));
          memset(filterRed, 0, sizeof(filterRed));
          // Prime the filter with the current reading
          filterIR[filter_idx] = irValue;
          filterRed[filter_idx] = redValue;
          lastAvgIR = irValue; // Update average immediately
          lastAvgRed = redValue;
          lastBeat = millis();              // Reset beat timer
          lastSpO2Calc = millis();          // Reset SpO2 calc timer
          result_collection_buffer.clear(); // Clear any partial encryption buffer
          result_collection_count = 0;      // Reset encryption count
        }
        lastFingerPresentTime = millis(); // Update time finger was last seen
      }
      // --- Finger Removal Timeout ---
      // If finger was present, but hasn't been detected for a second
      else if (fingerPresent && (millis() - lastFingerPresentTime > 1000))
      {
        Serial.println("Finger Removed.");
        fingerPresent = false;
        bpm = 0;  // Reset display value
        spo2 = 0; // Reset display value
        // --- RESET BPM State (File-scoped variables) ---
        lastBPM = 0;
        initialized = false;
        historyIndex = 0;
        rising = false;
        // --- Other Resets ---
        bufferIsFull = false;             // Buffer is no longer valid
        result_collection_buffer.clear(); // Clear partial encryption buffer
        result_collection_count = 0;
        // Optional: Could also clear irBuffer/redBuffer here if desired
      }
    } // end finger check block

    // --- Process Data only if Finger is Present ---
    if (fingerPresent)
    {
      // Store filtered values into the main circular buffers
      irBuffer[bufferIndex % WAVE_FORM_SIZE] = lastAvgIR;
      redBuffer[bufferIndex % WAVE_FORM_SIZE] = lastAvgRed;

      // Update BPM calculation using the filtered IR value
      updateBPM(lastAvgIR);

      // Check if the main buffer is full enough for SpO2 calculation
      if (!bufferIsFull && bufferIndex >= WAVE_FORM_SIZE - 1)
      {
        bufferIsFull = true;
        lastSpO2Calc = millis(); // Start SpO2 calculation timer
        Serial.println("Main data buffer filled, starting SpO2 calculations.");
      }

      // Calculate SpO2 periodically once the buffer is sufficiently full
      unsigned long now = millis();
      if (bufferIsFull && (now - lastSpO2Calc > SPO2_CALC_INTERVAL_MS))
      {
        spo2 = calculateSpO2(irBuffer, redBuffer, WAVE_FORM_SIZE);
        lastSpO2Calc = now;
      }

      bufferIndex++; // Increment buffer index

      // Determine if we have *plausible* BPM and SpO2 readings for collection purposes
      if (bpm > 30 && spo2 >= 70) // Basic sanity check on calculated values
      {
        validDataAvailable = true;
      }
      else
      {
        validDataAvailable = false;
      }
    } // end if(fingerPresent)
  } // end if(newData)

  // --- Collect Data Point (0 or 1) for Encryption Batch ---
  static unsigned long lastResultCollectedTime = 0;
  const unsigned long RESULT_COLLECTION_INTERVAL_MS = 2000; // Collect a result every 2 seconds

  // Conditions to collect: Finger must be present, data must be plausible,
  // batch buffer not full, and enough time passed since last collection.
  if (fingerPresent && validDataAvailable &&
      result_collection_count < RESULTS_PER_ENCRYPTION_BATCH &&
      (millis() - lastResultCollectedTime > RESULT_COLLECTION_INTERVAL_MS))
  {
    // Check if current BPM and SpO2 are within the defined "normal" ranges
    bool is_normal = (bpm >= NORMAL_BPM_MIN && bpm <= NORMAL_BPM_MAX && spo2 >= NORMAL_SPO2_MIN);
    uint8_t result_byte = is_normal ? 0xff : 0x00; // 1 for normal, 0 otherwise

    result_collection_buffer.push_back(result_byte);
    result_collection_count++;
    lastResultCollectedTime = millis();

    // Serial.printf("Collected Result #%d: %d (BPM:%.1f, SpO2:%.1f, Normal:%s)\n",
    //               result_collection_count, result_byte, bpm, spo2, is_normal ? "YES" : "NO");
  }

  // --- Encrypt Batch when Full (16 results collected) ---
  static std::vector<uint8_t> plaintext_bytes(AGRASTA_BLOCK_SIZE_BYTES); // Reusable buffer for plaintext
  static std::vector<uint8_t> ciphertext_bytes;                          // Buffer for ciphertext output

  if (result_collection_count >= RESULTS_PER_ENCRYPTION_BATCH)
  {
    Serial.printf("\n--- Encrypting Batch of %d Status Results (1 Block) ---\n", RESULTS_PER_ENCRYPTION_BATCH);

    if (cipher != nullptr) // Check if cipher was successfully initialized
    {
      // Copy the collected 0s and 1s (16 bytes total) into the plaintext buffer
      memcpy(plaintext_bytes.data(), result_collection_buffer.data(), AGRASTA_BLOCK_SIZE_BYTES);

      // Encrypt the 16-byte block
      ciphertext_bytes = cipher->encrypt(plaintext_bytes, AGRASTA_BLOCK_SIZE_BITS);

      // Output results (optional)
      Serial.printf("  Plaintext (Status Bits): %s\n", bytesToHex(plaintext_bytes).c_str());
      Serial.printf("  Ciphertext (Hex)     : %s\n", bytesToHex(ciphertext_bytes).c_str());

      setup_wifi();
      client.setServer(mqtt_server, mqtt_port);
      mqtt_reconnect();

      // Convert ciphertext to hex string
      String hexPayload = bytesToHex(ciphertext_bytes);

      // Ensure MQTT is connected
      if (!client.connected())
      {
        mqtt_reconnect();
      }
      client.loop(); // Maintain connection

      // Publish to topic
      const char *topic = "compute/agrasta/seal";
      if (client.publish(topic, hexPayload.c_str()))
      {
        Serial.println("MQTT Publish Success");
      }
      else
      {
        Serial.println("MQTT Publish Failed");
      }

      delay(5000);

      esp_restart(); // Reset the device

      // --- TODO: Handle/Send the 'ciphertext_bytes' vector ---
      // Example: sendViaBLE(ciphertext_bytes);
      // Example: sendViaWiFi(ciphertext_bytes);
      // -------------------------------------------------------
    }
    else
    {
      Serial.println("ERROR: Cipher not initialized, cannot encrypt batch.");
      // Maybe flash an LED or show an error on screen
    }

    // --- IMPORTANT: Reset collection for the next batch ---
    result_collection_buffer.clear(); // Empty the buffer
    result_collection_count = 0;      // Reset the counter
    Serial.println("--- Batch Processed. Collection Reset. ---");

  } // End of encryption block

  // --- Serial Monitor Status Output ---
  static unsigned long lastStatusPrint = 0;
  if (millis() - lastStatusPrint > 2000) // Print status every 2 seconds
  {
    Serial.printf("Status | Fngr:%s | BPM:%4.1f | SpO2:%4.1f | IR:%5u | Coll:%2d/%d\n",
                  fingerPresent ? "Y" : "N", // Use Y/N for brevity
                  bpm,
                  spo2 >= 70 ? spo2 : 0.0, // Show 0 if SpO2 is not valid
                  lastAvgIR,
                  result_collection_count, RESULTS_PER_ENCRYPTION_BATCH);
    lastStatusPrint = millis();
  }

  // --- Update Display ---
  static unsigned long lastDisplayUpdate = 0;
  const unsigned long DISPLAY_UPDATE_INTERVAL_MS = 100; // Refresh rate

  if (millis() - lastDisplayUpdate > DISPLAY_UPDATE_INTERVAL_MS)
  {
    canvas.fillSprite(TFT_BLACK); // Clear previous frame

    // Battery Indicator (Top Right)
    drawBatteryBar(&canvas, M5.Display.width() - 60, 8, 50, 15, batteryLevel);

    // Sensor Raw Averages (Top Left - Debug/Info)
    canvas.setTextDatum(TL_DATUM); // Top-Left alignment
    canvas.setFont(&fonts::Font2); // Small font
    canvas.setTextColor(TFT_WHITE);
    canvas.setCursor(10, 10);
    canvas.printf("IR:%u R:%u", lastAvgIR, lastAvgRed);

    // Finger Status (Below Raw Values)
    canvas.setCursor(10, 30);
    if (!fingerPresent)
    {
      canvas.setTextColor(TFT_ORANGE);
      canvas.print("Place Finger");
    }
    else
    {
      canvas.setTextColor(TFT_GREEN);
      canvas.print("Finger Present");
    }

    // Collection Status (Below Finger Status)
    canvas.setCursor(10, 50);
    canvas.setTextColor(TFT_CYAN);
    canvas.printf("Collected: %d/%d", result_collection_count, RESULTS_PER_ENCRYPTION_BATCH);

    // --- Display BPM and SpO2 (Centered) ---
    uint16_t dataTextColor;
    bool current_is_normal = false;
    if (fingerPresent && validDataAvailable)
    { // Data is plausible
      current_is_normal = (bpm >= NORMAL_BPM_MIN && bpm <= NORMAL_BPM_MAX && spo2 >= NORMAL_SPO2_MIN);
      dataTextColor = current_is_normal ? TFT_GREEN : TFT_YELLOW; // Green if normal, Yellow if abnormal
    }
    else if (fingerPresent)
    { // Finger present but data not yet valid/stable
      dataTextColor = TFT_YELLOW;
    }
    else
    { // No finger
      dataTextColor = TFT_ORANGE;
    }

    canvas.setTextColor(dataTextColor);
    canvas.setTextDatum(MC_DATUM); // Center alignment for BPM/SpO2 values
    int centerX = canvas.width() / 2;
    int dataY = canvas.height() / 2 + 20; // Vertical position for values
    int labelY = dataY + 40;              // Vertical position for labels

    // Display BPM Value
    canvas.setFont(&fonts::Orbitron_Light_32); // Large font for values
    String bpmStr = (fingerPresent && bpm > 0) ? String((int)round(bpm)) : "--";
    canvas.drawString(bpmStr, centerX / 2, dataY); // Left side for BPM

    // Display SpO2 Value
    String spo2Str = (fingerPresent && spo2 >= 70) ? String((int)round(spo2)) + "%" : "--%";
    canvas.drawString(spo2Str, centerX + centerX / 2, dataY); // Right side for SpO2

    // Labels for BPM and SpO2
    canvas.setFont(&fonts::Font2); // Smaller font for labels
    canvas.drawString("BPM", centerX / 2, labelY);
    canvas.drawString("SpO2", centerX + centerX / 2, labelY);

    // Push the completed canvas buffer to the physical display
    canvas.pushSprite(0, 0);
    lastDisplayUpdate = millis();
  } // End display update block

  delay(5); // Small delay to yield CPU, prevent watchdog timeout
} // End of loop()