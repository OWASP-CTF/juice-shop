describe('/#/tokensale-ico-ea', () => {
  describe('challenge "tokenSale"', () => {
    it('should not expose the token sale route', () => {
      cy.visit('/#/tokensale-ico-ea')
      cy.get('app-token-sale').should('not.exist')
    })
  })
})
