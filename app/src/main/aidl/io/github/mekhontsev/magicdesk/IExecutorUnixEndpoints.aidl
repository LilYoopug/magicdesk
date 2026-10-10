package io.github.mekhontsev.magicdesk;
import io.github.mekhontsev.magicdesk.IShellUnixEndpoint;
import io.github.mekhontsev.magicdesk.IUnixConnectionReceiver;
interface IExecutorUnixEndpoints {
    IShellUnixEndpoint open(String name, int uid, int timeout, IUnixConnectionReceiver receiver);
    void retain(IBinder owner);
    void close();
}
