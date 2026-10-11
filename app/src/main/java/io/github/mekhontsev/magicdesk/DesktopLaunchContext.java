package io.github.mekhontsev.magicdesk;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

/** Host operations required by the launch coordinator. */
interface DesktopLaunchContext {
    Context context();

    default void onMain(Runnable action) {
        if (Looper.myLooper() == Looper.getMainLooper()) action.run();
        else new Handler(Looper.getMainLooper()).post(action);
    }

    ToolLaunchTarget destination();

    default String destinationUniqueId() { return null; }

    void hideTransientUi();

    boolean launchAndroid(
            DesktopLaunchRequest request,
            Runnable onPrepared,
            DesktopActivityLaunchResult.Completion completion);

    default void launchConsole(DesktopLaunchRequest request, DesktopActivityLaunchResult.Completion completion) {
        var target = destination();
        var presentation = target.desktop ? DesktopLaunchPresentation.automatic() : request.presentation;
        BuiltInWindowLauncher.launch(context(), CommandConsoleActivity.createPreparedCommandIntent(context(),
                        request.exec.command, request.exec.workingDirectory, request.exec.backend),
                CommandConsoleActivity.launchTarget(), target, destinationUniqueId(),
                presentation.withInstancePolicy(DesktopTaskInstancePolicy.CREATE_NEW), error ->
                        completion.onComplete(error == null
                                ? DesktopActivityLaunchResult.unmanagedAccepted(target.displayId)
                                : DesktopActivityLaunchResult.failed(error)));
    }

    boolean isUnavailable();

    void onStarted(DesktopLaunchRequest request);

    void onCompleted(DesktopLaunchRequest request);

    void onUnavailable(DesktopLaunchRequest request);

    void onFailure(DesktopLaunchRequest request, Throwable error);
}
