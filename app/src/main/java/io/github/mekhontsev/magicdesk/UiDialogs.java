package io.github.mekhontsev.magicdesk;

import android.app.Activity;
import android.app.AlertDialog;

/** Native modals share the owner's appearance and inset policy, not its lifecycle callbacks. */
final class UiDialogs {
    private UiDialogs() {}

    static AlertDialog.Builder builder(Activity owner) {
        return new Builder(owner);
    }

    private static final class Builder extends AlertDialog.Builder {
        private final Activity owner;

        Builder(Activity owner) {
            super(owner);
            this.owner = owner;
        }

        @Override public AlertDialog create() {
            AlertDialog dialog = super.create();
            dialog.setOwnerActivity(owner);
            dialog.create();
            UiAppearance.dialog(dialog);
            DialogContentInsets.bind(dialog.findViewById(android.R.id.content), owner);
            return dialog;
        }
    }
}
