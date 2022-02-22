import * as InteropLib from 'cardano-hw-interop-lib'
import { isEqual, uniqWith, cloneDeep } from 'lodash'
import {
  TxWitnessByron,
  TxWitnessShelley,
  TxCborHex,
  TxWitnessKeys,
} from './types'
import { encodeCbor } from '../util'
import { CardanoEra } from '../types'
import { SigningParameters } from '../crypto-providers/types'

const TxByronWitness = (
  publicKey: Buffer, signature: Buffer, chaincode: Buffer, addressAttributes: object,
): TxWitnessByron => [publicKey, signature, chaincode, encodeCbor(addressAttributes)]

const TxShelleyWitness = (publicKey: Buffer, signature: Buffer): TxWitnessShelley => [publicKey, signature]

const _rawTxToTxSigned = (
  params: SigningParameters,
  byronWitnesses: TxWitnessByron[],
  shelleyWitnesses: TxWitnessShelley[],
): TxCborHex => {
  const {
    body, scriptWitnesses, datumWitnesses, redeemerWitnesses, scriptValidity, auxiliaryData,
  } = params.rawTx!

  // cardano-cli deduplicates the script witnesses before adding them to the signed transaction
  const scriptWitnessList = uniqWith((scriptWitnesses || []) as any[], isEqual)
  const datumWitnessList = (datumWitnesses || []) as any[]
  const redeemerWitnessList = (redeemerWitnesses || []) as any[]

  let nativeScriptWitnessList: unknown[] = []
  let plutusScriptWitnessList: unknown[] = []
  if (params.era === CardanoEra.ALONZO) {
    // In alonzo era txs, each native script is packed in a list with 0 literal, each plutus script
    // is packed in a list with 1 literal and they are all stored in scriptWitnessList.
    // We need to partition them back and unpack the actual scripts.
    nativeScriptWitnessList = scriptWitnessList.filter((s) => s[0] === 0).map((s) => s[1])
    plutusScriptWitnessList = scriptWitnessList.filter((s) => s[0] === 1).map((s) => s[1])
  } else {
    // In older txs, scriptWitnessList is just a list of native scripts.
    nativeScriptWitnessList = scriptWitnessList
  }

  const witnessSet = new Map<number, unknown[]>()

  if (shelleyWitnesses.length > 0) {
    witnessSet.set(TxWitnessKeys.SHELLEY, shelleyWitnesses)
  }

  if (nativeScriptWitnessList.length > 0) {
    witnessSet.set(TxWitnessKeys.NATIVE_SCRIPTS, nativeScriptWitnessList)
  }

  if (byronWitnesses.length > 0) {
    witnessSet.set(TxWitnessKeys.BYRON, byronWitnesses)
  }

  if (plutusScriptWitnessList.length > 0) {
    witnessSet.set(TxWitnessKeys.PLUTUS_SCRIPTS, plutusScriptWitnessList)
  }

  if (datumWitnessList.length > 0) {
    witnessSet.set(TxWitnessKeys.PLUTUS_DATA, datumWitnessList)
  }

  if (redeemerWitnessList.length > 0) {
    witnessSet.set(TxWitnessKeys.REDEEMERS, redeemerWitnessList)
  }

  const signedTx = {
    body, witnessSet, scriptValidity, auxiliaryData,
  }
  return InteropLib.encodeTx(signedTx).toString('hex') as TxCborHex
}

const TxSigned = (
  params: SigningParameters,
  byronWitnesses: TxWitnessByron[],
  shelleyWitnesses: TxWitnessShelley[],
): TxCborHex => {
  if (params.rawTx) {
    return _rawTxToTxSigned(params, byronWitnesses, shelleyWitnesses)
  }

  const witnessSet = cloneDeep(params.tx!.witnessSet) as Map<number, unknown[]>

  const byronWitnessesList = [
    ...witnessSet.get(TxWitnessKeys.BYRON) ?? [],
    byronWitnesses,
  ]
  if (byronWitnessesList.length > 0) {
    // cardano-cli deduplicates the witnesses before adding them to the signed transaction
    witnessSet.set(TxWitnessKeys.BYRON, uniqWith(byronWitnessesList, isEqual))
  }

  const shelleyWitnessesList = [
    ...witnessSet.get(TxWitnessKeys.SHELLEY) ?? [],
    shelleyWitnesses,
  ]
  if (shelleyWitnessesList.length > 0) {
    // cardano-cli deduplicates the witnesses before adding them to the signed transaction
    witnessSet.set(TxWitnessKeys.SHELLEY, uniqWith(shelleyWitnessesList, isEqual))
  }

  const signedTx = { ...params.tx!, witnessSet }
  return InteropLib.encodeTx(signedTx).toString('hex') as TxCborHex
}

export const containsVKeyWitnesses = (tx: InteropLib.Transaction): boolean => {
  const witnessSet = tx.witnessSet as Map<number, unknown[]>
  const shelleyWitnesses = witnessSet?.get(TxWitnessKeys.SHELLEY) || []
  const byronWitnesses = witnessSet?.get(TxWitnessKeys.BYRON) || []
  return [...shelleyWitnesses, ...byronWitnesses].length > 0
}

export {
  TxByronWitness,
  TxShelleyWitness,
  TxSigned,
}
