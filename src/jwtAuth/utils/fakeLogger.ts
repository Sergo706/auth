export const fakeLogger: any = {
    info: () => {},
    debug: () => {},
    error: () => {},
    child: () => fakeLogger
};
