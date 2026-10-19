# Temporary laboratory setup, sourced by the stock Snap launcher.
# Remove ~/.chromium-browser.init after the experiment.
export LD_PRELOAD="$SNAP_USER_COMMON/libgbm-discovery-probe.so${LD_PRELOAD:+:$LD_PRELOAD}"
export SHROOT_GBM_PROBE_ROOT="$SNAP_USER_COMMON/gbm-probe-root"
