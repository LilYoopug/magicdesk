package io.github.mekhontsev.magicdesk;
interface IShellUnixEndpoint {
    String filesystemPath();
    oneway void acknowledge(long serial);
    oneway void close();
}
