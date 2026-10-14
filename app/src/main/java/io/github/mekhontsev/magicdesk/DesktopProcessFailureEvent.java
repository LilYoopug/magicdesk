package io.github.mekhontsev.magicdesk;

import android.os.Parcel;
import android.os.Parcelable;
import org.json.JSONException;
import org.json.JSONObject;

/** Bounded failure evidence captured before the crashing task disappears. */
public final class DesktopProcessFailureEvent implements Parcelable {
    static final int MAX_MESSAGE_CHARS = 1_024;
    static final int MAX_STACK_CHARS = 12_000;
    final int type, pid, taskId, userId, displayId, windowingMode;
    final String processName, topActivity, reason, message, stackTrace;

    DesktopProcessFailureEvent(int type, String processName, int pid, int taskId,
            int userId, int displayId, int windowingMode, String topActivity,
            String reason, String message, String stackTrace) {
        this.type = type;
        this.processName = bounded(processName, 512);
        this.pid = pid;
        this.taskId = taskId;
        this.userId = userId;
        this.displayId = displayId;
        this.windowingMode = windowingMode;
        this.topActivity = bounded(topActivity, 1_024);
        this.reason = DesktopProcessFailure.compactReason(reason);
        this.message = bounded(message, MAX_MESSAGE_CHARS);
        this.stackTrace = bounded(stackTrace, MAX_STACK_CHARS);
    }

    String packageName() {
        int separator = processName.indexOf(':');
        return separator < 0 ? processName : processName.substring(0, separator);
    }

    String technicalDetail(String version) {
        StringBuilder detail = new StringBuilder(DesktopProcessFailure.technicalDetail(
                processName, pid, taskId, displayId, windowingMode, topActivity, reason))
                .append(" | user=").append(userId)
                .append(" | packageVersion=").append(bounded(version, 256));
        if (!message.isEmpty()) detail.append("\n message: ").append(indent(message));
        if (!stackTrace.isEmpty()) detail.append("\n stack:\n ").append(indent(stackTrace));
        return detail.toString();
    }

    JSONObject summary() throws JSONException {
        return new JSONObject().put("process", processName).put("pid", pid)
                .put("taskId", taskId).put("userId", userId).put("displayId", displayId)
                .put("windowingMode", windowingMode).put("topActivity", topActivity)
                .put("reason", reason).put("stackCaptured", !stackTrace.isEmpty());
    }

    private static String indent(String text) { return text.replace("\n", "\n "); }

    static String bounded(String text, int limit) {
        if (text == null) return "";
        String clean = text.replace("\u0000", "").replace("\r\n", "\n").replace('\r', '\n');
        if (clean.length() <= limit) return clean;
        int end = Character.isHighSurrogate(clean.charAt(limit - 1)) ? limit - 1 : limit;
        return clean.substring(0, end) + "\n[truncated]";
    }

    private DesktopProcessFailureEvent(Parcel source) {
        this(source.readInt(), source.readString(), source.readInt(), source.readInt(),
                source.readInt(), source.readInt(), source.readInt(), source.readString(),
                source.readString(), source.readString(), source.readString());
    }

    @Override public int describeContents() { return 0; }
    @Override public void writeToParcel(Parcel destination, int flags) {
        destination.writeInt(type);
        destination.writeString(processName);
        destination.writeInt(pid);
        destination.writeInt(taskId);
        destination.writeInt(userId);
        destination.writeInt(displayId);
        destination.writeInt(windowingMode);
        destination.writeString(topActivity);
        destination.writeString(reason);
        destination.writeString(message);
        destination.writeString(stackTrace);
    }

    public static final Creator<DesktopProcessFailureEvent> CREATOR = new Creator<>() {
        @Override public DesktopProcessFailureEvent createFromParcel(Parcel source) {
            return new DesktopProcessFailureEvent(source);
        }
        @Override public DesktopProcessFailureEvent[] newArray(int size) {
            return new DesktopProcessFailureEvent[size];
        }
    };
}
