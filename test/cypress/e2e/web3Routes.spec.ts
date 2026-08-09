describe('public Web3 routes', () => {
  it('does not expose the wallet, faucet, or sandbox applications', () => {
    for (const route of ['wallet-web3', 'bee-haven', 'web3-sandbox']) {
      cy.visit(`/#/${route}`)
      cy.get('app-wallet-web3, app-faucet, app-web3-sandbox').should('not.exist')
    }
  })
})
