import { deepStrictEqual } from "assert";
import sha256 from "universal-sha256-js/sha256.mjs";

import sign from "../sign.mjs";

const private_key = new Uint8Array([
  210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
  139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125,
]);

export default (tests) => {
  tests.add("ECDSA test.", async () => {
    const hash = await sha256(Uint8Array.from([104, 101, 108, 108, 111]));

    sign({ private_key, hash }).then(({ r, s }) => {
      deepStrictEqual(
        r,
        Uint8Array.from([
          23, 65, 177, 231, 159, 63, 28, 25, 165, 77, 134, 46, 57, 177, 238, 12,
          27, 154, 144, 172, 2, 178, 236, 72, 4, 137, 215, 73, 68, 45, 204, 89,
        ]),
        "Expected r signature."
      );
      deepStrictEqual(
        s,
        Uint8Array.from([
          111, 249, 137, 86, 106, 238, 64, 221, 142, 155, 69, 155, 220, 248,
          115, 86, 40, 253, 185, 203, 14, 216, 101, 226, 70, 25, 127, 31, 145,
          3, 72, 142,
        ]),
        "Expected s signature."
      );
    });
  });

  tests.add("ECDSA test 2 iterations.", async () => {
    const hash = await sha256(
      Uint8Array.from([
        75, 64, 14, 80, 102, 145, 71, 88, 235, 218, 14, 154, 227, 28, 80, 119,
        99, 141, 64, 3, 32, 154, 180, 208, 111, 159, 242, 81, 40, 228, 231, 137,
      ])
    );
    sign({ private_key, hash }).then(({ r, s }) => {
      deepStrictEqual(
        r,
        Uint8Array.from([
          72, 119, 153, 175, 250, 205, 95, 240, 175, 129, 65, 165, 241, 156, 94,
          5, 11, 62, 4, 242, 176, 82, 210, 128, 50, 153, 199, 248, 142, 62, 238,
          79,
        ]),
        "expected r value for 3 iterations"
      );
      deepStrictEqual(
        s,
        Uint8Array.from([
          49, 194, 138, 9, 93, 243, 130, 1, 210, 178, 11, 92, 186, 3, 250, 30,
          128, 152, 12, 196, 247, 1, 174, 129, 76, 218, 56, 145, 133, 186, 42,
          100,
        ]),
        "expected r value for 3 iterations"
      );
    });
  });

  tests.add("ECDSA test 3 iterations.", async () => {
    const hash = await sha256(
      Uint8Array.from([
        69, 190, 43, 207, 207, 204, 186, 186, 41, 243, 229, 40, 86, 150, 183,
        176, 50, 222, 50, 152, 13, 242, 56, 51, 159, 168, 98, 15, 76, 26, 229,
        68,
      ])
    );

    sign({ private_key, hash }).then(({ r, s }) => {
      deepStrictEqual(
        r,
        Uint8Array.from([
          77, 179, 117, 207, 35, 85, 114, 147, 158, 226, 74, 245, 183, 193, 235,
          254, 94, 235, 225, 57, 205, 172, 76, 28, 232, 114, 124, 152, 169, 107,
          179, 126,
        ]),
        "expected r value for 3 iterations"
      );
      deepStrictEqual(
        s,
        Uint8Array.from([
          97, 193, 51, 17, 33, 239, 215, 165, 234, 181, 56, 157, 219, 104, 227,
          162, 254, 117, 190, 81, 216, 165, 95, 159, 3, 115, 250, 179, 46, 181,
          116, 16,
        ]),
        "expected r value for 3 iterations"
      );
    });
  });

  tests.add("v expected 0", async () => {
    const { r, s, v } = await sign({
      private_key: Uint8Array.from([
        171, 209, 35, 208, 126, 4, 237, 27, 221, 89, 230, 143, 1, 241, 209, 116,
        11, 185, 87, 240, 82, 81, 52, 97, 243, 122, 3, 93, 4, 243, 118, 38,
      ]),
      hash: await sha256(
        Uint8Array.from([
          42, 2, 160, 5, 62, 90, 140, 247, 58, 86, 186, 15, 218, 17, 228, 217,
          46, 2, 56, 164, 162, 170, 116, 252, 207, 70, 213, 169, 16, 116, 104,
          64, 179, 11, 93, 97, 0, 203, 18, 176, 219, 213, 0, 0, 0, 0, 1, 0, 166,
          130, 52, 3, 234, 48, 85, 0, 0, 0, 87, 45, 60, 205, 205, 1, 80, 84, 85,
          53, 93, 26, 161, 130, 0, 0, 0, 0, 168, 237, 50, 50, 33, 80, 84, 85,
          53, 93, 26, 161, 130, 48, 77, 198, 14, 42, 56, 200, 32, 1, 0, 0, 0, 0,
          0, 0, 0, 4, 69, 79, 83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
      ),
    });

    deepStrictEqual(
      r,
      Uint8Array.from([
        102, 165, 252, 150, 141, 73, 254, 214, 156, 42, 57, 219, 7, 34, 0, 132,
        112, 59, 127, 168, 154, 221, 246, 159, 151, 21, 149, 148, 61, 22, 229,
        105,
      ])
    );

    deepStrictEqual(
      s,
      Uint8Array.from([
        71, 127, 123, 117, 148, 84, 17, 56, 39, 187, 32, 172, 17, 245, 92, 96,
        244, 158, 125, 55, 135, 175, 165, 177, 151, 146, 79, 168, 254, 40, 68,
        150,
      ])
    );

    deepStrictEqual(v, 0);

    const gt0x80 = await sign({
      private_key: Uint8Array.from([
        171, 209, 35, 208, 126, 4, 237, 27, 221, 89, 230, 143, 1, 241, 209, 116,
        11, 185, 87, 240, 82, 81, 52, 97, 243, 122, 3, 93, 4, 243, 118, 38,
      ]),
      hash: await sha256(
        Uint8Array.from(
          Buffer.from(
            "8a34ec7df1b8cd06ff4a8abbaa7cc50300823350cadc59ab296cb00d104d2b8ffb6f9061f41a6466f09b000000000110e77d792a77b39e000050d0e4e952320110e77d792a77b39e00000000a8ed32322100000000a868a45a2c000000000000000103706f6f03706f6f0101320001013200000000000000000000000000000000000000000000000000000000000000000000",
            "hex"
          )
        )
      ),
    });

    deepStrictEqual(
      gt0x80,
      {
        r: Uint8Array.from([
          125, 153, 29, 53, 50, 254, 78, 163, 251, 209, 202, 226, 198, 141, 87,
          176, 50, 164, 161, 223, 180, 0, 251, 147, 136, 174, 41, 198, 202, 76,
          171, 154,
        ]),
        s: Uint8Array.from([
          117, 74, 55, 83, 76, 159, 217, 167, 33, 55, 244, 36, 161, 89, 133, 89,
          167, 60, 97, 156, 142, 211, 135, 188, 248, 131, 7, 226, 5, 21, 35, 95,
        ]),
        v: 1,
      },
      "Equal or greater than 0x80."
    );
  });

  tests.add("Signature test", async () => {
    const hash = await sha256(
      Uint8Array.from(
        "8a34ec7df1b8cd06ff4a8abbaa7cc50300823350cadc59ab296cb00d104d2b8ffb6f9061f41a6466f09b000000000110e77d792a77b39e000050d0e4e952320110e77d792a77b39e00000000a8ed32322100000000a868a45a2c000000000000000103706f6f03706f6f0101320001013200000000000000000000000000000000000000000000000000000000000000000000"
          .match(/[a-fA-F0-9]{2}/gmu)
          .map((i) => `0x${i}`)
      )
    );

    const private_key = Uint8Array.from([
      171, 209, 35, 208, 126, 4, 237, 27, 221, 89, 230, 143, 1, 241, 209, 116,
      11, 185, 87, 240, 82, 81, 52, 97, 243, 122, 3, 93, 4, 243, 118, 38,
    ]);

    const r = Uint8Array.from([
      125, 153, 29, 53, 50, 254, 78, 163, 251, 209, 202, 226, 198, 141, 87, 176,
      50, 164, 161, 223, 180, 0, 251, 147, 136, 174, 41, 198, 202, 76, 171, 154,
    ]);

    const s = Uint8Array.from([
      117, 74, 55, 83, 76, 159, 217, 167, 33, 55, 244, 36, 161, 89, 133, 89,
      167, 60, 97, 156, 142, 211, 135, 188, 248, 131, 7, 226, 5, 21, 35, 95,
    ]);

    const sig = await sign({ hash, private_key });
    deepStrictEqual(sig.r, r);
    deepStrictEqual(sig.s, s);
    deepStrictEqual(sig.v, 1);
  });

  tests.add("Even more tests", async () => {
    const private_key = Uint8Array.from([
      210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28,
      230, 139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240,
      125,
    ]);

    const hash = await sha256(Uint8Array.from([23, 23, 123, 244]));
    const sig = await sign({ hash, private_key });

    deepStrictEqual(
      sig.r,
      Uint8Array.from([
        70, 123, 91, 92, 240, 57, 3, 198, 123, 104, 163, 14, 215, 216, 37, 254,
        167, 167, 134, 117, 209, 169, 175, 254, 181, 227, 153, 75, 219, 177,
        181, 223,
      ])
    );

    deepStrictEqual(sig.v, 1);
    deepStrictEqual(
      sig.s,
      Uint8Array.from([
        81, 218, 28, 35, 86, 146, 162, 4, 102, 101, 12, 156, 249, 71, 118, 41,
        243, 106, 151, 122, 221, 154, 230, 31, 199, 33, 26, 40, 34, 108, 10,
        176,
      ])
    );
  });
  tests.add("random value", async () => {});
};
