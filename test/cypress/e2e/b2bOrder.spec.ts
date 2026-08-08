describe('/b2b/v2/order', () => {
  describe('challenge "rce"', () => {
    it('should reject an infinite loop payload without evaluating it', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.login({ email: 'admin', password: 'admin123' })

          cy.window().then(async () => {
            const response = await fetch(
              `${Cypress.config('baseUrl')}/b2b/v2/orders/`,
              {
                method: 'POST',
                cache: 'no-cache',
                headers: {
                  'Content-type': 'application/json',
                  Authorization: `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                  orderLinesData: '(function dos() { while(true); })()'
                })
              }
            )
            expect(response.status).to.equal(400)
          })
        }
      })
    })
  })

  describe('challenge "rceOccupy"', () => {
    it('should reject a recursive regular expression payload without evaluating it', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.login({ email: 'admin', password: 'admin123' })
          cy.window().then(async () => {
            const response = await fetch(
              `${Cypress.config('baseUrl')}/b2b/v2/orders/`,
              {
                method: 'POST',
                cache: 'no-cache',
                headers: {
                  'Content-type': 'application/json',
                  Authorization: `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                  orderLinesData:
                    "/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')"
                })
              }
            )
            expect(response.status).to.equal(400)
          })
        }
      })
    })
  })
})
