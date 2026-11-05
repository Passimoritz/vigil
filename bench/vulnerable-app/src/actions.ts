'use server'
import { db } from './pool';

// Loescht eine Bestellung (Next.js Server Action)
export async function deleteOrder(id: string) {
  await db.order.delete({ where: { id } });
}
