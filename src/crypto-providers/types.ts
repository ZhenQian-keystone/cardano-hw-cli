import {
  SignedTxCborHex,
  _TxAux,
  _ShelleyWitness,
  _ByronWitness,
  _XPubKey,
} from '../transaction/types'
import { HwSigningData, BIP32Path } from '../types'

export type CryptoProvider = {
  signTx: (txAux: _TxAux, signingFiles: HwSigningData[], network: any) => Promise<SignedTxCborHex>,
  witnessTx: (
    txAux: _TxAux, signingFiles: HwSigningData[], network: any
  ) => Promise<_ShelleyWitness | _ByronWitness>
  getXPubKey: (path: BIP32Path) => Promise<_XPubKey>,
}
