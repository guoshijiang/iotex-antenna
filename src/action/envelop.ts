import actionPb from "./action_pb";
import { makeSigner } from "../crypto/crypto";
import { hash256b } from "../crypto/hash";

interface ITransfer {
  amount: string;
  recipient: string;
  payload: Buffer | string;
}

interface IAction {
  core: IActionCore | undefined;
  senderPubKey: Uint8Array | string;
  signature: Uint8Array | string;
}

interface IActionCore {
  version: number;
  nonce: string;
  gasLimit: string;
  gasPrice: string;
  transfer?: ITransfer | undefined;
}

// tslint:disable-next-line:no-any
function toActionTransfer(req: ITransfer | undefined): any {
  if (!req) {
    return undefined;
  }
  const pbTransfer = new actionPb.Transfer();
  pbTransfer.setAmount(req.amount);
  pbTransfer.setRecipient(req.recipient);
  pbTransfer.setPayload(req.payload);
  return pbTransfer;
}

export class Envelop {
  public version: number;
  public nonce: string;
  public gasLimit?: string | undefined;
  public gasPrice?: string | undefined;
  public transfer?: ITransfer | undefined;

  constructor(
    version: number,
    nonce: string,
    gasLimit?: string,
    gasPrice?: string
  ) {
    this.version = version;
    this.nonce = nonce;
    this.gasLimit = gasLimit;
    this.gasPrice = gasPrice;
  }

  // tslint:disable-next-line:cyclomatic-complexity
  public core(): actionPb.ActionCore {
    const gasLimit = this.gasLimit || "0";
    const gasPrice = this.gasPrice || "0";

    const pbActionCore = new actionPb.ActionCore();
    pbActionCore.setVersion(this.version);
    pbActionCore.setNonce(Number(this.nonce));
    pbActionCore.setGaslimit(Number(gasLimit));
    pbActionCore.setGasprice(gasPrice);
    if (this.transfer) {
      pbActionCore.setTransfer(toActionTransfer(this.transfer));
    }
    return pbActionCore;
  }

  public bytestream(): Uint8Array {
    return this.core().serializeBinary();
  }
}


export class SealedEnvelop {
  public act: Envelop;
  public senderPubKey: Buffer;
  public signature: Buffer;

  constructor(act: Envelop, senderPubKey: Buffer, signature: Buffer) {
    this.act = act;
    this.senderPubKey = senderPubKey;
    this.signature = signature;
  }

  public bytestream(): Uint8Array {
    const pbActionCore = this.act.core();
    const pbAction = new actionPb.Action();
    pbAction.setCore(pbActionCore);
    pbAction.setSenderpubkey(this.senderPubKey);
    pbAction.setSignature(this.signature);
    return pbAction.serializeBinary();
  }

  public hash(): string {
    return Buffer.from(hash256b(this.bytestream())).toString("hex");
  }

  public action(): IAction {
    const gasLimit = this.act.gasLimit || "0";
    const gasPrice = this.act.gasPrice || "0";

    return {
      core: {
        version: this.act.version,
        nonce: this.act.nonce,
        gasLimit: gasLimit,
        gasPrice: gasPrice,
        transfer: this.act.transfer,
      },
      senderPubKey: this.senderPubKey,
      signature: this.signature
    };
  }

  public static sign(
    privateKey: string,
    publicKey: string,
    act: Envelop
  ): SealedEnvelop {
    const h = hash256b(act.bytestream());
    const sign = Buffer.from(
      makeSigner(0)(h.toString("hex"), privateKey),
      "hex"
    );
    return new SealedEnvelop(act, Buffer.from(publicKey, "hex"), sign);
  }
}
