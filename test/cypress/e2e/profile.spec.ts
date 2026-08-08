describe('/profile', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'R4nd0m-Capybara-7!Quartz' })
  })
  describe('challenge "ssrf"', () => {
    it('should be possible to request internal resources using image upload URL', () => {
      cy.visit('/profile')

      cy.get('#url').type(
        `${Cypress.config('baseUrl')}/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3`
      )
      cy.get('#submitUrl').click()
      cy.visit('/')
      cy.expectChallengeSolved({ challenge: 'SSRF' })
    })
  })

  describe('challenge "usernameXss"', () => {
    it('renders a stored Pug script payload as text under a fixed CSP', () => {
      const payload = '\n                  script.\n                    alert(`xss`)'

      cy.visit('/profile')
      cy.get('#url').type(
        "https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'"
      )
      cy.get('#submitUrl').click()
      cy.request({
        method: 'POST',
        url: '/profile',
        form: true,
        body: { username: payload }
      })
      cy.visit('/profile')

      cy.get('.profile-username').should('have.text', payload).find('script').should('not.exist')
      cy.request('/profile').then((response) => {
        expect(response.headers['content-security-policy']).to.equal("img-src 'self' data: http: https:; script-src 'self'")
      })
      cy.request('/api/Challenges/?name=CSP Bypass').then((response) => {
        expect(response.body.data[0].solved).to.equal(false)
      })
    })
  })

  describe('challenge "ssti"', () => {
    it('renders a template expression literally without solving the challenge', () => {
      const payload = '#{7 * 7}'

      cy.visit('/profile')
      cy.get('#username').clear().type(payload, { parseSpecialCharSequences: false })
      cy.get('#submit').click()
      cy.get('.profile-username').should('have.text', payload).and('not.have.text', '49')
      cy.request(
        '/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3'
      )
      cy.request('/api/Challenges/?name=SSTi').then((response) => {
        expect(response.body.data[0].solved).to.equal(false)
      })
    })
  })

  describe('challenge "csrf"', () => {
    // FIXME Only works on Chrome <80 but Protractor uses latest Chrome version. Test can probably never be turned on again.
    xit('should be possible to perform a CSRF attack against the user profile page', () => {
      cy.visit('http://htmledit.squarefree.com')
      /* The script executed below is equivalent to pasting this string into http://htmledit.squarefree.com: */
      /* <form action="http://localhost:3000/profile" method="POST"><input type="hidden" name="username" value="CSRF"/><input type="submit"/></form><script>document.forms[0].submit();</script> */
      let document: any
      cy.window().then(() => {
        document
          .getElementsByName('editbox')[0]
          .contentDocument.getElementsByName(
            'ta'
          )[0].value = `<form action=\\"${Cypress.config('baseUrl')}/profile\\" 
        method=\\"POST\\">
        <input type=\\"hidden\\" name=\\"username\\" value=\\"CSRF\\"/>
        <input type=\\"submit\\"/>
        </form>
        <script>document.forms[0].submit();
        </script>
        `
      })
      // cy.expectChallengeSolved({ challenge: 'CSRF' })
    })

    xit('should be possible to fake a CSRF attack against the user profile page', () => {
      cy.visit('/')
      cy.window().then(async () => {
        const formData = new FormData()
        formData.append('username', 'CSRF')

        const response = await fetch(`${Cypress.config('baseUrl')}/profile`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/x-www-form-urlencoded',
            Authorization: `Bearer ${localStorage.getItem('token')}`,
            Origin: 'http://htmledit.squarefree.com', // FIXME Not allowed by browser due to "unsafe header not permitted"
            Cookie: `token=${localStorage.getItem('token')}` // FIXME Not allowed by browser due to "unsafe header not permitted"
          },
          body: formData
        })
        if (response.status === 200) {
          console.log('Success')
        }
      })
      // cy.expectChallengeSolved({ challenge: 'CSRF' })
    })
  })
})
