#!/bin/bash

# extract wg config file path, or use default
conf="$(jq -r .config_file_path db/server/global_settings.json || echo /etc/wireguard/wg0.conf)"
quick="${WG_QUICK:-wg-quick}"

# manage wireguard stop/start with the container
case $WGUI_MANAGE_START in (1|t|T|true|True|TRUE)
    $quick up "$conf"
    trap '$quick down "$conf"' SIGTERM # catches container stop
esac

# manage wireguard restarts
case $WGUI_MANAGE_RESTART in (1|t|T|true|True|TRUE)
    [[ -f $conf ]] || touch "$conf" # inotifyd needs file to exist
    inotifyd - "$conf":w | while read -r event file; do
        $quick down "$file"
        $quick up "$file"
    done &
esac


./wg-ui &
wait $!
