import { deepStrictEqual } from "assert";

import recover_public_key from "../src/recover_public_key";
import sha256 from "../src/sha256";
import { number_to_array } from "../src/utils";

const signature = {
  r: number_to_array(
    50172533143525448505731076092836454339589141171079665638497512992118311974590n
  ),
  s: number_to_array(
    3372897403575535231543296615264124933490702058654620386530787287980439847001n
  ),
  v: 0,
};

it("Public key with odd y coordinate.", async () => {
  const hash = await sha256(
    Uint8Array.from([2, 33, 65, 233, 23, 23, 123, 244, 23, 23, 123, 244])
  );
  const public_key = Uint8Array.from([
    2, 192, 222, 210, 188, 31, 19, 5, 251, 15, 170, 197, 230, 192, 62, 227, 161,
    146, 66, 52, 152, 84, 39, 182, 22, 124, 165, 105, 209, 61, 244, 53, 207,
  ]);

  deepStrictEqual(
    public_key,
    await recover_public_key({
      signature,
      hash,
    })
  );
});
