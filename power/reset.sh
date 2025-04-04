#!/bin/bash

source ~/.ha_creds.sh

curl -X POST -H "Authorization: Bearer ${HA_TOKEN}" -H "Content-Type: application/json" -d '{"entity_id": "switch.amdtestcontrol_reset_pin"}' ${HA_URL}/api/services/switch/turn_on
