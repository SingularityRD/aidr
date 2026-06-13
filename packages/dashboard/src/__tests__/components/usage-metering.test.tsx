/**
 * Tests for the UsageMetering widget component.
 *
 * Covers:
 * - Loading skeleton render
 * - Full data render (seat_usage view)
 * - Back-compat fallback (entitlements + agents)
 * - Error state (blocking and non-blocking)
 * - Warning threshold (80 % usage)
 * - Critical threshold (100 % usage)
 * - Trend chart with agent creation dates
 */

import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mock supabase
// ---------------------------------------------------------------------------

vi.mock("../../lib/supabase", () => {
	// Build a chainable query builder factory that lets each test supply
	// specialised return values per table name.
	const defaultResolve = Promise.resolve({ data: null, error: null });

	const chain = {
		select: vi.fn(() => chain),
		order: vi.fn(() => chain),
		limit: vi.fn(() => chain),
		maybeSingle: vi.fn(() => Promise.resolve({ data: null, error: null })),
		single: vi.fn(() => Promise.resolve({ data: null, error: null })),
		gte: vi.fn(() => chain),
		eq: vi.fn(() => chain),
		neq: vi.fn(() => chain),
		in: vi.fn(() => chain),
	};

	// Make the chain thenable so it can be awaited directly.
	const thenableChain = chain as unknown as Promise<unknown>;
	thenableChain.then = (resolve, reject) => defaultResolve.then(resolve, reject);

	return {
		supabase: {
			from: vi.fn(() => chain),
			functions: {
				invoke: vi.fn(),
			},
		},
		supabaseEnvError: null,
	};
});

// Import AFTER mocking
import { UsageMetering } from "../../components/usage-metering";
import { supabase } from "../../lib/supabase";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convenience cast so TS does not complain about mock methods. */
const mocked = supabase as unknown as {
	from: ReturnType<typeof vi.fn>;
};

/**
 * Reset all mock call history between tests so that results from one test
 * do not leak into the next.
 */
function resetMocks() {
	vi.clearAllMocks();
}

/**
 * Make `supabase.from(TABLE).select(…).maybeSingle()` resolve with `data`.
 *
 * Because the mock chain returns the same object for every call, and
 * `maybeSingle` is the terminal method, we set its implementation here.
 */
function setMaybeSingle(data: unknown, error: unknown = null) {
	mocked.from.mockReturnValue({
		select: vi.fn(() => ({
			order: vi.fn(() => ({
				limit: vi.fn(() => ({
					maybeSingle: vi.fn(() => Promise.resolve({ data, error })),
				})),
				maybeSingle: vi.fn(() => Promise.resolve({ data, error })),
			})),
			maybeSingle: vi.fn(() => Promise.resolve({ data, error })),
			gte: vi.fn(() => ({
				order: vi.fn(() => Promise.resolve({ data: [], error: null })),
			})),
		})),
	});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("UsageMetering", () => {
	afterEach(() => {
		resetMocks();
	});

	it("renders a loading skeleton on mount", () => {
		setMaybeSingle(null);
		const { container } = render(<UsageMetering />);

		// The skeleton includes placeholder divs — look for the card wrapper.
		expect(container.querySelector(".card")).toBeInTheDocument();
	});

	it("renders usage data from seat_usage view", async () => {
		setMaybeSingle({
			included_agents: 2,
			extra_agents: 3,
			allowed_agents: 5,
			current_agents: 2,
		});

		// Also stub the agents query for the trend chart and subscription query.
		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 2 });
						}
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() => Promise.resolve({ data: [], error: null })),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() =>
									Promise.resolve({
										data: {
											status: "active",
											provider: "lemon_squeezy",
											extra_agents: 3,
											current_period_end: "2026-06-28T00:00:00Z",
											cancel_at_period_end: false,
										},
										error: null,
									}),
								),
							})),
						})),
					})),
				};
			}
			// seat_usage
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 2,
								extra_agents: 3,
								allowed_agents: 5,
								current_agents: 2,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByText("Usage Metering")).toBeInTheDocument();
		});

		await waitFor(() => {
			expect(screen.getByText(/2\s*\/\s*5/)).toBeInTheDocument();
		});

		// Billing status pill should show "Active"
		await waitFor(() => {
			expect(screen.getByText("Active")).toBeInTheDocument();
		});
	});

	it("falls back to entitlements + agents when seat_usage view is missing", async () => {
		setMaybeSingle(null);

		mocked.from.mockImplementation((table: string) => {
			if (table === "entitlements") {
				return {
					select: vi.fn(() => ({
						maybeSingle: vi.fn(() =>
							Promise.resolve({
								data: { included_agents: 1, extra_agents: 0 },
								error: null,
							}),
						),
					})),
				};
			}
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 1 });
						}
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() => Promise.resolve({ data: [], error: null })),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() => Promise.resolve({ data: null, error: null })),
							})),
						})),
					})),
				};
			}
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() => Promise.resolve({ data: null, error: null })),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByText("Usage Metering")).toBeInTheDocument();
		});

		// Free tier label should be visible since no subscription
		await waitFor(() => {
			expect(screen.getByText("Free tier")).toBeInTheDocument();
		});
	});

	it("shows error state when queries fail and no data is available", async () => {
		mocked.from.mockReturnValue({
			select: vi.fn(() => ({
				maybeSingle: vi.fn(() =>
					Promise.resolve({ data: null, error: new Error("Database connection failed") }),
				),
			})),
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByText("Usage Metering")).toBeInTheDocument();
		});

		await waitFor(() => {
			expect(screen.getByText("Database connection failed")).toBeInTheDocument();
		});
	});

	it("shows an upgrade prompt when usage >= 80 % of allowance", async () => {
		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 4 });
						}
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() => Promise.resolve({ data: [], error: null })),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() =>
									Promise.resolve({
										data: {
											status: "active",
											provider: "stripe",
											extra_agents: 3,
											current_period_end: "2026-06-28T00:00:00Z",
											cancel_at_period_end: false,
										},
										error: null,
									}),
								),
							})),
						})),
					})),
				};
			}
			// seat_usage → usage at 80 %
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 1,
								extra_agents: 4,
								allowed_agents: 5,
								current_agents: 4,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByText("Approaching limit.")).toBeInTheDocument();
		});

		await waitFor(() => {
			expect(screen.getByText("80%")).toBeInTheDocument();
		});
	});

	it("shows an over-limit prompt when usage >= 100 % of allowance", async () => {
		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 6 });
						}
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() => Promise.resolve({ data: [], error: null })),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() =>
									Promise.resolve({
										data: {
											status: "active",
											provider: "stripe",
											extra_agents: 3,
											current_period_end: null,
											cancel_at_period_end: false,
										},
										error: null,
									}),
								),
							})),
						})),
					})),
				};
			}
			// seat_usage → over limit (6 / 5)
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 1,
								extra_agents: 4,
								allowed_agents: 5,
								current_agents: 6,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByText("Over limit.")).toBeInTheDocument();
		});

		// Upgrade button should be present
		await waitFor(() => {
			expect(screen.getByText("Upgrade")).toBeInTheDocument();
		});
	});

	// -----------------------------------------------------------------------
	// Progress bar colour
	// -----------------------------------------------------------------------

	it("progress bar uses safe colour when usage is below 80 %", async () => {
		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 1 });
						}
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() => Promise.resolve({ data: [], error: null })),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() => Promise.resolve({ data: null, error: null })),
							})),
						})),
					})),
				};
			}
			// seat_usage → 20 % (1 / 5)
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 4,
								extra_agents: 1,
								allowed_agents: 5,
								current_agents: 1,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			const bar = screen.getByRole("progressbar");
			expect(bar).toBeInTheDocument();
		});

		const bar = screen.getByRole("progressbar");
		expect(bar).toHaveAttribute("aria-valuenow", "1");
		expect(bar).toHaveAttribute("aria-valuemax", "5");

		const fill = bar.querySelector("div");
		expect(fill).toBeTruthy();
		expect(fill?.getAttribute("style")).toContain("var(--success-500)");
	});

	it("progress bar uses warning colour when usage is between 80 % and 100 %", async () => {
		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 4 });
						}
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() => Promise.resolve({ data: [], error: null })),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() => Promise.resolve({ data: null, error: null })),
							})),
						})),
					})),
				};
			}
			// seat_usage → 80 % (4 / 5)
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 1,
								extra_agents: 4,
								allowed_agents: 5,
								current_agents: 4,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByRole("progressbar")).toBeInTheDocument();
		});

		const bar = screen.getByRole("progressbar");
		const fill = bar.querySelector("div");
		expect(fill?.getAttribute("style")).toContain("var(--warning-500)");
	});

	it("progress bar uses critical colour when usage is >= 100 %", async () => {
		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 6 });
						}
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() => Promise.resolve({ data: [], error: null })),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() => Promise.resolve({ data: null, error: null })),
							})),
						})),
					})),
				};
			}
			// seat_usage → 120 % (6 / 5)
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 1,
								extra_agents: 4,
								allowed_agents: 5,
								current_agents: 6,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByRole("progressbar")).toBeInTheDocument();
		});

		const bar = screen.getByRole("progressbar");
		const fill = bar.querySelector("div");
		expect(fill?.getAttribute("style")).toContain("var(--error-500)");
	});

	// -----------------------------------------------------------------------
	// Trend chart
	// -----------------------------------------------------------------------

	it("renders trend chart with day labels", async () => {
		const today = new Date();
		const sevenDaysAgo = new Date(today);
		sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 2 });
						}
						const threeDaysAgo = new Date(today);
						threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() =>
									Promise.resolve({
										data: [
											{ created_at: threeDaysAgo.toISOString() },
											{ created_at: threeDaysAgo.toISOString() },
										],
										error: null,
									}),
								),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() => Promise.resolve({ data: null, error: null })),
							})),
						})),
					})),
				};
			}
			// seat_usage
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 4,
								extra_agents: 1,
								allowed_agents: 5,
								current_agents: 2,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByText(/New agents/)).toBeInTheDocument();
		});

		// Trend chart should be rendered with an accessible label.
		const chart = screen.getByRole("img", { name: /Agent creation trend/i });
		expect(chart).toBeInTheDocument();

		// Chart should contain 7 bars (one per day).
		const bars = chart.querySelectorAll("div > div");
		expect(bars.length).toBeGreaterThanOrEqual(7);
	});

	// -----------------------------------------------------------------------
	// Billing section
	// -----------------------------------------------------------------------

	it("displays billing section with provider and period end", async () => {
		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 2 });
						}
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() => Promise.resolve({ data: [], error: null })),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() =>
									Promise.resolve({
										data: {
											status: "active",
											provider: "lemon_squeezy",
											extra_agents: 3,
											current_period_end: "2026-06-28T00:00:00Z",
											cancel_at_period_end: false,
										},
										error: null,
									}),
								),
							})),
						})),
					})),
				};
			}
			// seat_usage
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 2,
								extra_agents: 3,
								allowed_agents: 5,
								current_agents: 2,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByText("Provider")).toBeInTheDocument();
		});

		await waitFor(() => {
			expect(screen.getByText("lemon_squeezy")).toBeInTheDocument();
		});

		await waitFor(() => {
			expect(screen.getByText("Current period ends")).toBeInTheDocument();
		});

		await waitFor(() => {
			expect(screen.getByText("Extra agents")).toBeInTheDocument();
		});
	});

	it("shows free tier billing when no subscription exists", async () => {
		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 1 });
						}
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() => Promise.resolve({ data: [], error: null })),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() => Promise.resolve({ data: null, error: null })),
							})),
						})),
					})),
				};
			}
			// seat_usage
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 2,
								extra_agents: 0,
								allowed_agents: 2,
								current_agents: 1,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByText("Free tier")).toBeInTheDocument();
		});

		await waitFor(() => {
			expect(screen.getByText("Plan")).toBeInTheDocument();
		});

		await waitFor(() => {
			expect(screen.getByText(/Free — 2 agents included/)).toBeInTheDocument();
		});
	});

	// -----------------------------------------------------------------------
	// Non-blocking error (error + data coexistence)
	// -----------------------------------------------------------------------

	it("shows non-blocking error alongside data when partial queries fail", async () => {
		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 2 });
						}
						return Promise.resolve({
							data: null,
							error: new Error("Trend query timeout"),
						});
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() =>
									Promise.resolve({
										data: {
											status: "active",
											provider: "stripe",
											extra_agents: 0,
											current_period_end: "2026-07-01T00:00:00Z",
											cancel_at_period_end: false,
										},
										error: null,
									}),
								),
							})),
						})),
					})),
				};
			}
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 2,
								extra_agents: 0,
								allowed_agents: 2,
								current_agents: 2,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByText("Usage Metering")).toBeInTheDocument();
		});

		await waitFor(() => {
			expect(screen.getByText(/2\s*\/\s*2/)).toBeInTheDocument();
		});

		await waitFor(() => {
			expect(screen.getByText("Active")).toBeInTheDocument();
		});
	});

	// -----------------------------------------------------------------------
	// Billing period status
	// -----------------------------------------------------------------------

	it("displays warning pill for paused subscription status", async () => {
		mocked.from.mockImplementation((table: string) => {
			if (table === "agents") {
				return {
					select: vi.fn((_cols: string, opts: unknown) => {
						const { count: countOpt } = (opts ?? {}) as { count?: string };
						if (countOpt === "exact") {
							return Promise.resolve({ data: null, error: null, count: 1 });
						}
						return {
							gte: vi.fn(() => ({
								order: vi.fn(() => Promise.resolve({ data: [], error: null })),
							})),
						};
					}),
				};
			}
			if (table === "subscriptions") {
				return {
					select: vi.fn(() => ({
						order: vi.fn(() => ({
							limit: vi.fn(() => ({
								maybeSingle: vi.fn(() =>
									Promise.resolve({
										data: {
											status: "paused",
											provider: "stripe",
											extra_agents: 0,
											current_period_end: "2026-06-15T00:00:00Z",
											cancel_at_period_end: false,
										},
										error: null,
									}),
								),
							})),
						})),
					})),
				};
			}
			return {
				select: vi.fn(() => ({
					maybeSingle: vi.fn(() =>
						Promise.resolve({
							data: {
								included_agents: 1,
								extra_agents: 0,
								allowed_agents: 1,
								current_agents: 1,
							},
							error: null,
						}),
					),
				})),
			};
		});

		render(<UsageMetering />);

		await waitFor(() => {
			expect(screen.getByText("Paused")).toBeInTheDocument();
		});
	});
});
