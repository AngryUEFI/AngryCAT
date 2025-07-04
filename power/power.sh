#!/usr/bin/env bash
set -eo pipefail

# load HA_TOKEN and HA_URL
source ~/.ha_creds.sh

# --- CONFIGURATION MAPS ---
# map device numbers (1–5) to entity prefixes
declare -A DEVICE_MAP=(
  [1]="amdtestcontrolam4_3"
  [2]="amdtestcontrol"
  [3]="amdtestcontrolam4_2"
  [4]="amdtestcontrolam5_1"
  [5]="amdtestcontrol5"
)

# map action types to entity suffixes
declare -A ACTION_MAP=(
  [short]="power_pin_short"
  [long]="power_pin_long"
  [reset]="reset_pin"
  [led]="power_led"
)

# --- USAGE CHECK ---
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <action> <number>"
  echo "  action ∈ ${!ACTION_MAP[@]}"
  echo "  number ∈ ${!DEVICE_MAP[@]}"
  exit 1
fi

action=$1
num=$2

# validate inputs
if [[ -z "${ACTION_MAP[$action]:-}" ]]; then
  echo "Error: invalid action. Choose one of: ${!ACTION_MAP[@]}"
  exit 1
fi
if [[ -z "${DEVICE_MAP[$num]:-}" ]]; then
  echo "Error: invalid device number. Choose one of: ${!DEVICE_MAP[@]}"
  exit 1
fi

prefix="${DEVICE_MAP[$num]}"
suffix="${ACTION_MAP[$action]}"

if [[ "$action" == "led" ]]; then
  # GET the binary_sensor state and extract .state
  entity_id="binary_sensor.${prefix}_${suffix}"
  curl -s \
    -H "Authorization: Bearer ${HA_TOKEN}" \
    -H "Content-Type: application/json" \
    "${HA_URL}/api/states/${entity_id}" \
  | jq -r '.state'
else
  # POST to turn on the switch
  entity_id="switch.${prefix}_${suffix}"
  curl -s -X POST \
    -H "Authorization: Bearer ${HA_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"entity_id\": \"${entity_id}\"}" \
    "${HA_URL}/api/services/switch/turn_on"
fi
