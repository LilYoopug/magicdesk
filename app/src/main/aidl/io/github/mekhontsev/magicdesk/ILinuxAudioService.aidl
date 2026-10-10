package io.github.mekhontsev.magicdesk;
import io.github.mekhontsev.magicdesk.ILinuxAudioLease;
interface ILinuxAudioService {
    ILinuxAudioLease acquire(String owner, IBinder lifetime);
}
