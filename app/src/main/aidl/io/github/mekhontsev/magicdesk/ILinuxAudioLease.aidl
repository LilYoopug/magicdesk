package io.github.mekhontsev.magicdesk;
import android.os.ParcelFileDescriptor;
interface ILinuxAudioLease {
    void accept(int protocol, in ParcelFileDescriptor socket);
    long[] snapshot();
    void close();
}
