package io.github.mekhontsev.magicdesk;

import android.view.View;
import android.widget.ImageView;

/** A recycled or detached view cannot receive another application's artwork. */
final class ApplicationIconBinding implements View.OnAttachStateChangeListener {
    private final ImageView view;
    private final DesktopApplicationShortcut shortcut;
    private final String termuxPackage;
    private final ApplicationIconSubscription subscription;

    static void bind(ImageView view, DesktopApplicationShortcut shortcut) { bind(view, shortcut, null); }

    static void bind(ImageView view, DesktopApplicationShortcut shortcut, String termuxPackage) {
        clear(view);
        var binding = new ApplicationIconBinding(view, shortcut, termuxPackage);
        view.setTag(R.id.application_icon_binding, binding);
        view.addOnAttachStateChangeListener(binding);
        binding.render();
        if (view.isAttachedToWindow()) binding.onViewAttachedToWindow(view);
    }

    static void clear(ImageView view) {
        if (view.getTag(R.id.application_icon_binding) instanceof ApplicationIconBinding binding) {
            binding.subscription.close();
            view.removeOnAttachStateChangeListener(binding);
            view.setTag(R.id.application_icon_binding, null);
        }
    }

    private ApplicationIconBinding(ImageView view, DesktopApplicationShortcut shortcut, String termuxPackage) {
        this.view = view;
        this.shortcut = shortcut;
        this.termuxPackage = termuxPackage;
        subscription = new ApplicationIconSubscription(view.getContext(), this::render);
    }

    private void render() {
        view.setImageDrawable(DesktopApplicationIconResolver.resolve(view.getContext(), shortcut, termuxPackage));
    }

    @Override public void onViewAttachedToWindow(View ignored) {
        subscription.set(ApplicationIcons.key(shortcut, termuxPackage));
        render();
    }

    @Override public void onViewDetachedFromWindow(View ignored) { subscription.close(); }
}
