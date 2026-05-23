import type { createSimpleAuth } from './index.js';
type SimpleAuth = ReturnType<typeof createSimpleAuth>;
export type RippleContext = {
    request: Request;
    params: Record<string, string>;
};
export type RippleAuthAdapterOptions = {
    getAuth(): SimpleAuth;
};
export declare function createRippleAuthHandlers(options: RippleAuthAdapterOptions): {
    handleAuth(context: RippleContext): Promise<Response>;
    handleBootstrap(context: RippleContext): Promise<Response>;
};
export declare function handleRippleBootstrap(context: RippleContext, auth: SimpleAuth): Promise<Response>;
export declare function handleRippleAuth(context: RippleContext, auth: SimpleAuth): Promise<Response>;
export {};
//# sourceMappingURL=ripple.d.ts.map