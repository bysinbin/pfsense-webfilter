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
extra_commands="reload status restart"

command="/usr/local/sbin/poseafilterd"
command_args="-c /var/etc/poseafilter"
pidfile="/var/run/${name}.pid"
sup_pidfile="/var/run/${name}_sup.pid"

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
    if pgrep -q poseafilterd; then
        echo "poseafilter is already running."
        return 0
    fi
    # Use FreeBSD supervisor daemon with auto-restart on crash (-r -R 1)
    /usr/sbin/daemon -r -R 1 -P ${sup_pidfile} -p ${pidfile} -f ${command} ${command_args}
    sleep 1
    if pgrep -q poseafilterd; then
        echo "poseafilter started successfully."
        return 0
    fi
    echo "Failed to start poseafilterd."
    return 1
}

poseafilter_stop() {
    echo "Stopping PoseaFilter daemon..."
    if [ -f "${sup_pidfile}" ] && [ -s "${sup_pidfile}" ]; then
        kill -TERM $(cat ${sup_pidfile}) 2>/dev/null
        rm -f ${sup_pidfile}
    fi
    if [ -f "${pidfile}" ] && [ -s "${pidfile}" ]; then
        kill -TERM $(cat ${pidfile}) 2>/dev/null
        rm -f ${pidfile}
    fi
    killall -TERM poseafilterd 2>/dev/null
}

poseafilter_reload() {
    echo "Reloading PoseaFilter configuration..."
    poseafilter_stop
    sleep 1
    poseafilter_start
}

poseafilter_status() {
    if pgrep -q poseafilterd; then
        echo "poseafilter is running (PID: $(pgrep poseafilterd))."
        return 0
    fi
    echo "poseafilter is not running."
    return 1
}

start_cmd="poseafilter_start"
stop_cmd="poseafilter_stop"
reload_cmd="poseafilter_reload"
status_cmd="poseafilter_status"

run_rc_command "$1"
