/** Minimal ambient WebAssembly/fetch declarations for runtimes typed without the DOM lib. */
declare namespace WebAssembly {
  type ImportExportKind = "function" | "table" | "memory" | "global";
  type ExportValue = ((...args: number[]) => unknown) | Memory;
  type Exports = Record<string, ExportValue>;
  type Imports = Record<string, Record<string, (...args: number[]) => unknown>>;
  type ModuleImportDescriptor = {
    module: string;
    name: string;
    kind: ImportExportKind;
  };

  class Memory {
    readonly buffer: ArrayBuffer;
  }

  // oxlint-disable-next-line no-extraneous-class, no-static-only-class -- ambient declaration of the WebAssembly.Module constructor value
  class Module {
    static imports(module: Module): ModuleImportDescriptor[];
  }

  class Instance {
    readonly exports: Exports;
  }

  class RuntimeError extends Error {
    // oxlint-disable-next-line custom-error-definition -- ambient declaration; a literal type is the only way to pin the name in a .d.ts
    override name: "RuntimeError";
  }

  function instantiate(
    bytes: ArrayBufferLike | ArrayBufferView,
    importObject?: Imports,
  ): Promise<{ module: Module; instance: Instance }>;

  function compile(bytes: ArrayBufferLike | ArrayBufferView): Promise<Module>;
}

// oxlint-disable-next-line no-implicit-globals -- declares fetch for runtimes typed without the DOM lib
declare function fetch(input: URL | string): Promise<{
  ok: boolean;
  status: number;
  arrayBuffer: () => Promise<ArrayBuffer>;
}>;
