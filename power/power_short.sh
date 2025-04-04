#!/bin/bash

source ~/.ha_creds.sh

curl -X POST -H "Authorization: Bearer ${HA_TOKEN}" -H "Content-Type: application/json" -d '{"entity_id": "switch.amdtestcontrol_power_pin_short"}' ${HA_URL}/api/services/switch/turn_on
