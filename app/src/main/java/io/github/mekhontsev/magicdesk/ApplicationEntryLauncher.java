package io.github.mekhontsev.magicdesk;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Dispatches Desktop Entry recipes independently of their UI or automation caller. */
final class ApplicationEntryLauncher {
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    static void launch(Context context, DesktopLaunchRequest request, ToolLaunchTarget target,
            String uniqueId, BooleanSupplier alive, Consumer<Throwable> complete) {
        launch(context, request, target, uniqueId, null, alive, complete);
    }

    static void launch(Context context, DesktopLaunchRequest request, ToolLaunchTarget target,
            String uniqueId, android.os.CancellationSignal cancellation, BooleanSupplier alive, Consumer<Throwable> complete) {
        TaskCommandQueue.execute(() -> {
            try {
                target.requireCurrent(DesktopRuntimeBridge.workspaceDisplayIds());
                InteractiveActivityLaunch.requireDestination(context, target.displayId, uniqueId);
                if (!alive.getAsBoolean()) return;
                if (target.desktop) {
                    boolean accepted = DesktopRuntimeBridge.launchAutomationRequest(request, target.displayId);
                    MAIN.post(() -> {
                        if (alive.getAsBoolean()) complete.accept(accepted ? null
                                : new IllegalStateException("application launch was rejected"));
                    });
                } else {
                    MAIN.post(() -> {
                        if (!alive.getAsBoolean()) return;
                        try {
                            new DesktopLaunchCoordinator(new StandaloneDesktopLaunchContext(
                                    context, target.displayId, uniqueId, cancellation)).launch(request, result -> {
                                if (alive.getAsBoolean()) complete.accept(result.succeeded() ? null
                                        : new IllegalStateException(result.error));
                            });
                        } catch (RuntimeException error) { complete.accept(error); }
                    });
                }
            } catch (java.io.IOException | RuntimeException error) {
                MAIN.post(() -> { if (alive.getAsBoolean()) complete.accept(error); });
            }
        });
    }

    static DesktopLaunchRequest present(DesktopLaunchRequest request, ToolLaunchTarget target,
            DesktopLaunchPresentation presentation) {
        DesktopLaunchPresentation selected = presentation.mode != DesktopLaunchMode.AUTO ? presentation
                : target.desktop ? request.presentation.withInstancePolicy(presentation.instancePolicy)
                : DesktopLaunchPresentation.forMode(DesktopLaunchMode.FULLSCREEN)
                        .withInstancePolicy(presentation.instancePolicy);
        if (!target.desktop) OrdinaryActivityLaunch.requirePresentation(selected);
        return request.withPresentation(selected);
    }

    private ApplicationEntryLauncher() { }
}
