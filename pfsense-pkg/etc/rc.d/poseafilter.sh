#!/bin/sh
#
# PROVIDE: poseafilter
# REQUIRE: DAEMON NETWORKING
# BEFORE: LOGIN
# KEYWORD: shutdown
#

. /etc/rc.subr

name="poseafilter"
rcvar="poseafilter_enable"

command="/usr/local/sbin/poseafilterd"
command_args="-c /var/etc/poseafilter"
pidfile="/var/run/${name}.pid"

load_rc_config $name

: ${poseafilter_enable:="YES"}

poseafilter_start() {
    echo "Starting PoseaFilter daemon for pfSense..."
    if [ ! -d "/var/etc/poseafilter" ]; then
        mkdir -p /var/etc/poseafilter
    fi
    if [ ! -d "/var/log/poseafilter" ]; then
        mkdir -p /var/log/poseafilter
    fi
    /usr/sbin/daemon -p ${pidfile} -f ${command} ${command_args}
}

poseafilter_stop() {
    echo "Stopping PoseaFilter daemon..."
    if [ -f "${pidfile}" ]; then
        kill -TERM $(cat ${pidfile}) 2>/dev/null
        rm -f ${pidfile}
    else
        killall -TERM poseafilterd 2>/dev/null
    fi
}

poseafilter_reload() {
    echo "Reloading PoseaFilter configuration..."
    if [ -f "${pidfile}" ]; then
        kill -HUP $(cat ${pidfile}) 2>/dev/null
    else
        killall -HUP poseafilterd 2>/dev/null
    fi
}

start_cmd="poseafilter_start"
stop_cmd="poseafilter_stop"
reload_cmd="poseafilter_reload"

run_rc_command "$1"
