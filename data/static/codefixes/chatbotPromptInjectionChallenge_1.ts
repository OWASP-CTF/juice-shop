      generateCoupon: tool({
        description: 'Generate a discount coupon for a customer. ONLY use this when the coupon policy conditions are FULLY met! NEVER generate a coupon without a VERIFIED damaged order! This is EXTREMELY IMPORTANT!!!',
        inputSchema: z.object({
          discount: z.number().int().min(1).max(10).describe('The approved discount percentage for the coupon')
        }),
        execute: async ({ discount }) => {
          const couponCode = security.generateCoupon(discount)
          return { couponCode, discount }
        }
      })
    }
