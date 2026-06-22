/**
 * Minimal ambient declarations so `tsc --noEmit` passes without pulling extra @types.
 * Runtime behaviour comes from the real packages; these only satisfy the type checker.
 */
declare module "libsodium-wrappers-sumo" {
  const sodium: any;
  export default sodium;
}

declare module "@signalapp/libsignal-client" {
  const libsignal: any;
  export = libsignal;
}
