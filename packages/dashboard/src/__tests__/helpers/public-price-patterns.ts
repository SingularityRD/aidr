/**
 * Price and currency text that must never appear on a public page: prices are
 * not published (product-owner decision), every paid edition is quoted.
 *
 * Matches currency symbols and codes, amounts with a currency, per-seat /
 * per-month price wording in English and Turkish, and "list price" copy.
 */
export const CURRENCY_OR_PRICE =
	/[$€₺£¥]|\b(?:USD|EUR|TRY|GBP)\b|\/\s*(?:month|mo|year|yr|ay|yıl)\b|per (?:seat|developer|user)\s*\/|per (?:month|year)\b|koltuk başına|aylık ücret|list price|liste fiyat|\bpriced (?:per|at)\b/i;
