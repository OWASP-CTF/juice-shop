import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { Wallet } from 'ethers'
import { createWalletProof, verifyWalletProof } from '../../routes/nftMint'

void describe('NFT mint wallet proof', () => {
  void it('accepts a signature from the claimed wallet only once', async () => {
    const wallet = Wallet.createRandom()
    const proof = createWalletProof(wallet.address)
    assert.ok(proof)
    const signature = await wallet.signMessage(proof.message)

    assert.equal(verifyWalletProof(wallet.address, proof.nonce, signature), true)
    assert.equal(verifyWalletProof(wallet.address, proof.nonce, signature), false)
  })

  void it('rejects a valid signature from a different wallet', async () => {
    const claimedWallet = Wallet.createRandom()
    const signingWallet = Wallet.createRandom()
    const proof = createWalletProof(claimedWallet.address)
    assert.ok(proof)
    const signature = await signingWallet.signMessage(proof.message)

    assert.equal(verifyWalletProof(claimedWallet.address, proof.nonce, signature), false)
  })
})
