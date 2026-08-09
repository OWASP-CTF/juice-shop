      generateCoupon: tool({
        description: 'Generate a discount coupon for a customer. Only use this when the coupon policy conditions are fully met.',
        inputSchema: z.object({
          discount: z.number().max(10).describe('The discount percentage for the coupon (maximum 10)'),
          orderId: z.string().regex(/^[0-9a-f]{4}-[0-9a-f]{16}$/i).describe('The order ID for the coupon')
        }),
        execute: async ({ discount, orderId }) => {
          const userId = getVerifiedUserId(req)
          if (!userId) return { error: 'Customer not authenticated' }
          const order = await db.ordersCollection.findOne({ orderId, UserId: userId, status: 'DAMAGED' })
          if (!order) return { error: 'Order does not belong to the current customer' }
          const couponCode = security.generateCoupon(discount)
          return { couponCode, discount }
        }
      }),

      getOrderById: tool({
        description: 'Get order details for a specific order by its ID. Only returns the order if it belongs to the current customer.',
        inputSchema: z.object({
          orderId: z.string().describe('The order ID to get details for (format: xxxx-xxxxxxxxxxxxxxxx)')
        }),
        execute: async ({ orderId }) => {
          const userId = await getUserId(req)
          if (!userId) return { error: 'Customer not authenticated' }

          const user = await UserModel.findByPk(userId, { attributes: ['email'] })
          if (!user) return { error: 'Customer not found' }

          const order = await db.ordersCollection.findOne({ orderId })

          if (!order) return { error: 'Order not found' }
          if (order.email !== user.email) return { error: 'Order does not belong to the current customer' }

          return order
        }
      })
    }
