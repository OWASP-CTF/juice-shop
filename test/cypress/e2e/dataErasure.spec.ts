describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'R4nd0m-Capybara-7!Quartz' })
  })

  describe('challenge "lfr"', () => {
    it('should reject a local file read attack', () => {
      cy.window().then(async () => {
        const params = 'layout=../package.json'

        const response = await fetch(`${Cypress.config('baseUrl')}/dataerasure`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/x-www-form-urlencoded',
            Origin: `${Cypress.config('baseUrl')}/`,
            Cookie: `token=${localStorage.getItem('token')}`
          },
          body: params
        })
        expect(response.status).to.equal(400)
      })
      cy.visit('/')
      cy.request('/api/Challenges/?name=Local File Read').then((response) => {
        expect(response.body.data[0].solved).to.equal(false)
      })
    })
  })
})
