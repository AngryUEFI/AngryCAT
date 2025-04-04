#!/bin/bash

# Prints either "on" or "off"

source ~/.ha_creds.sh

curl -s -H "Authorization: Bearer ${HA_TOKEN}" -H "Content-Type: application/json" ${HA_URL}/api/states/binary_sensor.amdtestcontrol_power_led | jq -r '.state'
