describe('/#/register', () => {
  beforeEach(() => {
    cy.visit('/#/register')
  })

  describe('challenge "persistedXssUser"', () => {
    beforeEach(() => {
      cy.login({
        email: 'admin',
        password: 'admin123'
      })
    })

    // Regression test: email is now always sanitized server-side
    // (see models/user.ts), so the "Client-side XSS Protection" challenge
    // can never be solved even when the REST API is called directly.
    it('should sanitize XSS payloads submitted directly via the REST API', async () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.window().then(async () => {
            const response = await fetch(
              `${Cypress.config('baseUrl')}/api/Users/`,
              {
                method: 'POST',
                cache: 'no-cache',
                headers: {
                  'Content-type': 'application/json'
                },
                body: JSON.stringify({
                  email: '<iframe src="javascript:alert(`xss`)">',
                  password: 'XSSed',
                  passwordRepeat: 'XSSed',
                  role: 'admin'
                })
              }
            )
            const user = await response.json()
            expect(user.data.email).to.not.contain('<iframe')
          })

          cy.visit('/#/administration')

          cy.request({
            method: 'GET',
            url: '/api/Challenges/?name=Client-side XSS Protection',
            timeout: 60000
          }).then((res) => {
            const challenge = res.body.data[0]
            // eslint-disable-next-line @typescript-eslint/no-unused-expressions
            expect(challenge.solved).to.be.false
          })
        }
      })
    })
  })

  describe('challenge "registerAdmin"', () => {
    it('should not be possible to register admin user using REST API', () => {
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
        const body = await response.json()
        expect(response.status).to.equal(201)
        expect(body.data.role).to.equal('customer')
      })
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
