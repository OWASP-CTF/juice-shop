import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { Wallet } from 'ethers'
import { createWalletExploitProof, verifyWalletExploitProof } from '../../routes/web3Wallet'

void describe('wallet exploit ownership proof', () => {
  void it('accepts a valid wallet proof only once', async () => {
    const wallet = Wallet.createRandom()
    const proof = createWalletExploitProof(wallet.address)
    assert.ok(proof)
    const signature = await wallet.signMessage(proof.message)

    assert.equal(verifyWalletExploitProof(wallet.address, proof.nonce, signature), true)
    assert.equal(verifyWalletExploitProof(wallet.address, proof.nonce, signature), false)
  })

  void it('rejects a proof signed by another wallet', async () => {
    const claimedWallet = Wallet.createRandom()
    const signingWallet = Wallet.createRandom()
    const proof = createWalletExploitProof(claimedWallet.address)
    assert.ok(proof)
    const signature = await signingWallet.signMessage(proof.message)

    assert.equal(verifyWalletExploitProof(claimedWallet.address, proof.nonce, signature), false)
  })
})
