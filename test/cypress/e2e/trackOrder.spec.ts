describe('/#/track-order', () => {
  describe('challenge "reflectedXss"', () => {
    it('should render an order ID as text without solving the challenge', () => {
      const orderId = '5267-f9cd5882f54c75a3'
      const payload = '<iframe src="javascript:alert(`xss`)">'

      cy.intercept('GET', `/rest/track-order/${orderId}`, {
        statusCode: 200,
        body: {
          status: 'success',
          data: [{ orderId: payload, products: [], eta: '1', bonus: 0, delivered: false }]
        }
      }).as('trackOrder')

      cy.visit(`/#/track-result?id=${orderId}`)
      cy.wait('@trackOrder')
      cy.get('h1 code').should('have.text', payload).find('iframe').should('not.exist')

      cy.request('/api/Challenges/?name=Reflected XSS').then((response) => {
        expect(response.body.data[0].solved).to.equal(false)
      })
    })
  })
})
