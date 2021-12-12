import { InputInfo, SigResult } from "@sensible-contract/abstract-wallet";
import * as bsv from "@sensible-contract/bsv";
import { BN } from "@sensible-contract/bsv";
const { Script } = bsv;
const { Interpreter } = Script;
const Interp = Interpreter;

const flags =
  Interp.SCRIPT_ENABLE_MAGNETIC_OPCODES |
  Interp.SCRIPT_ENABLE_MONOLITH_OPCODES | // TODO: to be removed after upgrade to bsv 2.0
  Interp.SCRIPT_VERIFY_STRICTENC |
  Interp.SCRIPT_ENABLE_SIGHASH_FORKID |
  Interp.SCRIPT_VERIFY_LOW_S |
  Interp.SCRIPT_VERIFY_NULLFAIL |
  Interp.SCRIPT_VERIFY_DERSIG |
  Interp.SCRIPT_VERIFY_MINIMALDATA |
  Interp.SCRIPT_VERIFY_NULLDUMMY |
  Interp.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
  Interp.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
  Interp.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
const Signature = bsv.crypto.Signature;
export const DEFAULT_SIGHASH_TYPE =
  Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;
const P2PKH_UNLOCK_SIZE = 1 + 1 + 71 + 1 + 33;
const P2PKH_DUST_AMOUNT = 135;
const CHANGE_OUTPUT_SIZE = 34;
export const PLACE_HOLDER_SIG =
  "41682c2074686973206973206120706c61636520686f6c64657220616e642077696c6c206265207265706c6163656420696e207468652066696e616c207369676e61747572652e00";
export const PLACE_HOLDER_PUBKEY =
  "41682c2074686973206973206120706c61636520686f6c64657220616e64207769";
function satoshisToBSV(satoshis: number) {
  return (satoshis / 100000000).toFixed(8);
}
export function numberToBuffer(n: number) {
  let str = n.toString(16);
  if (str.length % 2 == 1) {
    str = "0" + str;
  }
  return Buffer.from(str, "hex");
}
export class TxComposer {
  private tx: bsv.Transaction;
  private inputInfos: InputInfo[] = [];
  feeRate: number = 0.5;
  dustLimitFactor: number = 300;

  changeAddress: string = "";
  changeOutputIndex: number = -1;

  private static defaultFeeRate = 0.5;
  private static defaultDustLimitFactor = 300;

  static setGlobalConfig(
    defaultFeeRate: number,
    defaultDustLimitFactor: number
  ) {
    this.defaultFeeRate = defaultFeeRate;
    this.defaultDustLimitFactor = defaultDustLimitFactor;
  }

  constructor(tx?: bsv.Transaction) {
    this.tx = tx || new bsv.Transaction();
    this.feeRate = TxComposer.defaultFeeRate;
    this.dustLimitFactor = TxComposer.defaultDustLimitFactor;
  }

  toObject() {
    let composer = {
      tx: this.tx.toObject(),
      inputInfos: this.inputInfos,
      feeRate: this.feeRate,
      dustLimitFactor: this.dustLimitFactor,
      changeOutputIndex: this.changeOutputIndex,
      changeAddress: this.changeAddress,
    };
    return composer;
  }

  static fromObject(composerObj: any) {
    let txObj = composerObj.tx;
    let tx = new bsv.Transaction();
    txObj.inputs.forEach((v) => {
      tx.addInput(new bsv.Transaction.Input(v));
    });
    txObj.outputs.forEach((v) => {
      tx.addOutput(new bsv.Transaction.Output(v));
    });
    tx.nLockTime = txObj.nLockTime;
    tx.version = txObj.version;

    let txComposer = new TxComposer(tx);
    txComposer.inputInfos = composerObj.inputInfos;
    txComposer.feeRate = composerObj.feeRate;
    txComposer.dustLimitFactor = composerObj.dustLimitFactor;
    txComposer.changeOutputIndex = composerObj.changeOutputIndex;
    txComposer.changeAddress = composerObj.changeAddress;
    return txComposer;
  }

  getDustThreshold(size: number) {
    return Math.ceil(
      (Math.ceil((250 * (size + 9 + 148)) / 1000) * this.dustLimitFactor) / 100
    );
  }

  getRawHex() {
    return this.tx.serialize(true);
  }

  getTx() {
    return this.tx;
  }
  getTxId() {
    return this.tx.id;
  }

  getInput(inputIndex: number) {
    return this.tx.inputs[inputIndex];
  }

  getOutput(outputIndex: number) {
    return this.tx.outputs[outputIndex];
  }

  appendP2PKHInput(utxo: {
    address: bsv.Address | string;
    satoshis: number;
    txId: string;
    outputIndex: number;
  }) {
    this.tx.addInput(
      new bsv.Transaction.Input.PublicKeyHash({
        output: new bsv.Transaction.Output({
          script: bsv.Script.buildPublicKeyHashOut(utxo.address),
          satoshis: utxo.satoshis,
        }),
        prevTxId: utxo.txId,
        outputIndex: utxo.outputIndex,
        script: bsv.Script.empty(),
      })
    );
    const inputIndex = this.tx.inputs.length - 1;
    return inputIndex;
  }

  appendInput(input: {
    txId: string;
    outputIndex: number;
    lockingScript?: bsv.Script;
    satoshis?: number;
  }) {
    this.tx.addInput(
      new bsv.Transaction.Input({
        output: new bsv.Transaction.Output({
          script: input.lockingScript,
          satoshis: input.satoshis,
        }),
        prevTxId: input.txId,
        outputIndex: input.outputIndex,
        script: bsv.Script.empty(),
      })
    );
    const inputIndex = this.tx.inputs.length - 1;
    return inputIndex;
  }

  appendP2PKHOutput(output: {
    address: bsv.Address | string;
    satoshis: number;
  }) {
    this.tx.addOutput(
      new bsv.Transaction.Output({
        script: new bsv.Script(new bsv.Address(output.address)),
        satoshis: output.satoshis,
      })
    );
    const outputIndex = this.tx.outputs.length - 1;
    return outputIndex;
  }

  appendOutput(output: { lockingScript: bsv.Script; satoshis: number }) {
    this.tx.addOutput(
      new bsv.Transaction.Output({
        script: output.lockingScript,
        satoshis: output.satoshis,
      })
    );
    const outputIndex = this.tx.outputs.length - 1;
    return outputIndex;
  }

  appendOpReturnOutput(opreturnData: any) {
    this.tx.addOutput(
      new bsv.Transaction.Output({
        script: bsv.Script.buildSafeDataOut(opreturnData),
        satoshis: 0,
      })
    );
    const outputIndex = this.tx.outputs.length - 1;
    return outputIndex;
  }

  clearChangeOutput() {
    if (this.changeOutputIndex != -1) {
      this.tx.outputs.splice(this.changeOutputIndex, 1);
      this.changeOutputIndex = 0;
    }
  }

  appendChangeOutput(changeAddress: bsv.Address | string) {
    //Calculate the fee and determine whether to change
    //If there is change, it will be output in the last item
    const unlockSize =
      this.tx.inputs.filter((v) => v.output.script.isPublicKeyHashOut())
        .length * P2PKH_UNLOCK_SIZE;
    let fee = Math.ceil(
      (this.tx.toBuffer().length + unlockSize + CHANGE_OUTPUT_SIZE) *
        this.feeRate
    );

    let changeAmount = this.getUnspentValue() - fee;
    if (changeAmount >= P2PKH_DUST_AMOUNT) {
      this.changeOutputIndex = this.appendP2PKHOutput({
        address: changeAddress,
        satoshis: changeAmount,
      });
    } else {
      this.changeOutputIndex = -1;
    }
    this.changeAddress = changeAddress.toString();
    return this.changeOutputIndex;
  }

  unlockP2PKHInput(
    privateKey: bsv.PrivateKey,
    inputIndex: number,
    sighashType = DEFAULT_SIGHASH_TYPE
  ) {
    const tx = this.tx;
    const sig = new bsv.Transaction.Signature({
      publicKey: privateKey.publicKey,
      prevTxId: tx.inputs[inputIndex].prevTxId,
      outputIndex: tx.inputs[inputIndex].outputIndex,
      inputIndex,
      signature: bsv.Transaction.Sighash.sign(
        tx,
        privateKey,
        sighashType,
        inputIndex,
        tx.inputs[inputIndex].output.script,
        tx.inputs[inputIndex].output.satoshisBN
      ),
      sigtype: sighashType,
    });

    tx.inputs[inputIndex].setScript(
      bsv.Script.buildPublicKeyHashIn(
        sig.publicKey,
        sig.signature.toDER(),
        sig.sigtype
      )
    );
  }

  getTxFormatSig(
    privateKey: bsv.PrivateKey,
    inputIndex: number,
    sighashType = DEFAULT_SIGHASH_TYPE
  ) {
    return bsv.Transaction.Sighash.sign(
      this.tx,
      privateKey,
      sighashType,
      inputIndex,
      this.getInput(inputIndex).output.script,
      new BN(this.getInput(inputIndex).output.satoshis),
      flags
    )
      .toTxFormat()
      .toString("hex");
  }

  getPreimage(inputIndex: number, sighashType = DEFAULT_SIGHASH_TYPE) {
    return bsv.Transaction.Sighash.sighashPreimage(
      this.tx,
      sighashType,
      inputIndex,
      this.getInput(inputIndex).output.script,
      new BN(this.getInput(inputIndex).output.satoshis),
      flags
    ).toString("hex");
  }

  getUnspentValue() {
    const inputAmount = this.tx.inputs.reduce(
      (pre, cur) => cur.output.satoshis + pre,
      0
    );
    const outputAmount = this.tx.outputs.reduce(
      (pre, cur) => cur.satoshis + pre,
      0
    );

    let unspentAmount = inputAmount - outputAmount;
    return unspentAmount;
  }

  getFinalFeeRate() {
    let unspent = this.getUnspentValue();
    let txSize = this.tx.toBuffer().length;
    return unspent / txSize;
  }

  /**
   * get the inputInfos to sign with transaction.
   * @returns
   */
  getInputInfos() {
    return this.inputInfos;
  }

  setInputInfos(inputInfos: InputInfo[]) {
    this.inputInfos = inputInfos;
  }

  /**
   * add input's info for wallet to sign.
   * @param param0
   */
  addInputInfo({
    inputIndex,
    sighashType = DEFAULT_SIGHASH_TYPE,
    address,
  }: {
    inputIndex: number;
    sighashType?: number;
    address?: number | string;
  }) {
    this.inputInfos.push({
      inputIndex,
      scriptHex: this.getInput(inputIndex).output.script.toHex(),
      satoshis: this.getInput(inputIndex).output.satoshis,
      sighashType,
      address,
    });
  }

  getPrevoutsHash() {
    let prevouts = Buffer.alloc(0);
    this.tx.inputs.forEach((input) => {
      const indexBuf = Buffer.alloc(4, 0);
      indexBuf.writeUInt32LE(input.outputIndex);
      prevouts = Buffer.concat([
        prevouts,
        Buffer.from(input.prevTxId).reverse(),
        indexBuf,
      ]);
    });
    return bsv.crypto.Hash.sha256sha256(prevouts).toString("hex");
  }

  checkFeeRate() {
    let feeRate = this.getFinalFeeRate();
    if (feeRate < this.feeRate) {
      throw new Error(
        `Insufficient balance.The fee rate should not be less than ${this.feeRate}, but in the end it is ${feeRate}.`
      );
    }
  }

  /**
   * get the change output with UTXO format.
   * @returns
   */
  getChangeUtxo() {
    let output = this.getOutput(this.changeOutputIndex);
    if (output) {
      return {
        txId: this.getTxId(),
        outputIndex: this.changeOutputIndex,
        satoshis: output.satoshis,
        address: this.changeAddress,
      };
    }
  }

  unlock(sigResults: SigResult[]) {
    this.inputInfos.forEach(({ inputIndex, sighashType, scriptHex }, index) => {
      let input = this.tx.inputs[inputIndex];
      let sigInfo = sigResults[index];
      let publicKey = new bsv.PublicKey(sigInfo.publicKey);
      let _sig = bsv.crypto.Signature.fromString(sigInfo.sig);
      _sig.nhashtype = sighashType;
      if (input.script.toHex()) {
        let _sig2 = _sig.toTxFormat();
        let oldSigHex = Buffer.concat([
          numberToBuffer(PLACE_HOLDER_SIG.length / 2),
          Buffer.from(PLACE_HOLDER_SIG, "hex"),
        ]).toString("hex");

        let newSigHex = Buffer.concat([
          numberToBuffer(_sig2.length),
          _sig2,
        ]).toString("hex");

        let oldPubKeyHex = Buffer.concat([
          numberToBuffer(PLACE_HOLDER_PUBKEY.length / 2),
          Buffer.from(PLACE_HOLDER_PUBKEY, "hex"),
        ]).toString("hex");

        const pubkeyBuffer = publicKey.toBuffer();
        let newPubKeyHex = Buffer.concat([
          numberToBuffer(pubkeyBuffer.length),
          pubkeyBuffer,
        ]).toString("hex");

        input.setScript(
          new bsv.Script(
            input.script
              .toHex()
              .replace(oldSigHex, newSigHex)
              .replace(oldPubKeyHex, newPubKeyHex)
          )
        );
      } else {
        const signature = new bsv.Transaction.Signature({
          publicKey,
          prevTxId: input.prevTxId,
          outputIndex: input.outputIndex,
          inputIndex: inputIndex,
          signature: _sig,
          sigtype: sighashType,
        });
        input.setScript(
          bsv.Script.buildPublicKeyHashIn(
            signature.publicKey,
            signature.signature.toDER(),
            signature.sigtype
          )
        );
      }
    });
  }

  dumpTx(network: "mainnet" | "testnet" = "mainnet") {
    let tx = this.tx;
    const version = tx.version;
    const size = tx.toBuffer().length;
    const inputAmount = tx.inputs.reduce(
      (pre, cur) => cur.output.satoshis + pre,
      0
    );
    const outputAmount = tx.outputs.reduce((pre, cur) => cur.satoshis + pre, 0);
    let feePaid = inputAmount - outputAmount;

    const feeRate = (feePaid / size).toFixed(4);

    console.log(`
  =============================================================================================
  Summary
    txid:     ${tx.id}
    Size:     ${size}
    Fee Paid: ${satoshisToBSV(feePaid)}
    Fee Rate: ${feeRate} sat/B
    Detail:   ${tx.inputs.length} Inputs, ${tx.outputs.length} Outputs
  ----------------------------------------------------------------------------------------------
  ${tx.inputs
    .map((input, index) => {
      let type = "";
      if (input.output.script.isPublicKeyHashOut()) {
        type = "standard";
      } else if (input.output.script.isSafeDataOut()) {
        type = "OP_RETURN";
      } else {
        type = "nonstandard";
      }
      let str = `
  =>${index}    ${
        type == "standard"
          ? input.output.script.toAddress(network).toString()
          : type == "OP_RETURN"
          ? "OP_RETURN" + " ".repeat(34 - 9)
          : "nonstandard" + " ".repeat(34 - 11)
      }    ${satoshisToBSV(input.output.satoshis)} BSV
         lock-size:   ${input.output.script.toBuffer().length}
         unlock-size: ${input.script.toBuffer().length}
         via ${input.prevTxId.toString("hex")} [${input.outputIndex}]
  `;
      return str;
    })
    .join("")}
  Input total: ${satoshisToBSV(
    tx.inputs.reduce((pre, cur) => pre + cur.output.satoshis, 0)
  )} BSV
  ----------------------------------------------------------------------------------------------
  ${tx.outputs
    .map((output, index) => {
      let type = "";
      if (output.script.isPublicKeyHashOut()) {
        type = "standard";
      } else if (output.script.isSafeDataOut()) {
        type = "OP_RETURN";
      } else {
        type = "nonstandard";
      }
      let str = `
  =>${index}    ${
        type == "standard"
          ? output.script.toAddress(network).toString()
          : type == "OP_RETURN"
          ? "OP_RETURN" + " ".repeat(34 - 9)
          : "nonstandard" + " ".repeat(34 - 11)
      }    ${satoshisToBSV(output.satoshis)} BSV
         size: ${output.script.toBuffer().length}
      `;
      return str;
    })
    .join("")}
  Output total: ${satoshisToBSV(
    tx.outputs.reduce((pre, cur) => pre + cur.satoshis, 0)
  )} BSV
  =============================================================================================
     `);
  }
}
