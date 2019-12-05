/**
 * See https://github.com/herumi/mcl-wasm for more details
 * or mcl.js to see more available functions and implementation details
 */
declare module "mcl-wasm" {
    // Curves
    const BN254: number;
    const BN381_1: number;
    const BN381_2: number;
    const BN462: number;
    const BN_SNARK1: number;
    const BLS12_381: number;
    const SECP224K1: number;
    const SECP256K1: number;
    const SECP384R1: number;
    const NIST_P192: number;
    const NIST_P224: number;
    const NIST_P256: number;

    function init(curveType: number): Promise<void>;

    class Common {
        public getStr(base?: number): string;
        public deserializeHexStr(s: string): void;
        public serializeToHexStr(): string;
    }

    class Fr extends Common {
        public setByCSPRNG(): void;
        public isOne(): boolean;
        public isZero(): boolean;
        public isEqual(el: Fr): boolean;

        private forceFr(): void; // trick to force nominal typing
    }

    class G1 extends Common {
        public isZero(): boolean;
        public isEqual(el: G1): boolean;

        private forceG1(): void; // trick to force nominal typing
    }

    class G2 extends Common {
        public isZero(): boolean;
        public isEqual(el: G2): boolean;

        private forceG2(): void; // trick to force nominal typing
    }

    class GT extends Common {
        public isZero(): boolean;
        public isEqual(el: GT): boolean;

        private forceGT(): void; // trick to force nominal typing
    }

    function hashToFr(s: string): Fr;
    function hashAndMapToG1(s: string): G1;
    function hashAndMapToG2(s: string): G2;

    function add(x: Fr, y: Fr): Fr;
    function add(x: G1, y: G1): G1;
    function add(x: G2, y: G2): G2;
    function add(x: GT, y: GT): GT;

    function sub(x: Fr, y: Fr): Fr;
    function sub(x: G1, y: G1): G1;
    function sub(x: G2, y: G2): G2;
    function sub(x: GT, y: GT): GT;

    function mul(x: Fr, y: Fr): Fr;
    function mul(x: G1, y: Fr): G1;
    function mul(x: G2, y: Fr): G2;
    function mul(x: GT, y: GT): GT;

    function div(x: Fr, y: Fr): Fr;
    function div(x: GT, y: GT): GT;

    function pairing(P: G1, Q: G2): GT;
    function pow(x: GT, y: Fr): GT;

    function inv(x: Fr): Fr;
    function inv(x: GT): GT;

    function neg(x: Fr): Fr;

    function deserializeHexStrToFr(hexStr: string): Fr;
    function deserializeHexStrToG1(hexStr: string): G1;
    function deserializeHexStrToG2(hexStr: string): G2;
    function deserializeHexStrToGT(hexStr: string): GT;
}
