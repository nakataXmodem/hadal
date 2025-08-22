#!/usr/bin/env python3
import argparse
import asyncio
import sys
import random
from ipaddress import ip_network, IPv4Address

from sqlalchemy import select, text

from models import NetworkBlock
from database import get_db_session, engine


async def add_network_block(subnet_str: str) -> int:
	# Validate and normalize subnet (e.g., "192.168.1.5/24" -> "192.168.1.0/24")
	try:
		net = ip_network(subnet_str, strict=False)
	except ValueError as e:
		print(f"Invalid subnet '{subnet_str}': {e}")
		return 2

	normalized = str(net)

	async with get_db_session() as session:
		# Check if it already exists
		result = await session.execute(
			select(NetworkBlock).where(NetworkBlock.network == normalized)
		)
		existing = result.scalar_one_or_none()

		if existing:
			print(f"Network block '{normalized}' already exists (id={existing.id}). Skipping.")
			return 0

		# Insert new row with status PENDING
		nb = NetworkBlock(network=normalized, status="PENDING")
		session.add(nb)
		await session.commit()
		await session.refresh(nb)

		print(f"Inserted network block '{normalized}' with id={nb.id}.")
		return 0


async def add_network_blocks(count: int) -> int:
	"""Add N unique public IPv4 /24 blocks near a random existing block.

	Picks a random existing subnet as a seed, then alternates above and below
	(+1, -1, +2, -2, ...) selecting the next non-existing public /24 subnets.
	Skips private/reserved/unroutable ranges.
	"""
	if count <= 0:
		print("Count must be > 0")
		return 2

	EXCLUDED = [
		ip_network("0.0.0.0/8"),
		ip_network("10.0.0.0/8"),
		ip_network("100.64.0.0/10"),
		ip_network("127.0.0.0/8"),
		ip_network("169.254.0.0/16"),
		ip_network("172.16.0.0/12"),
		ip_network("192.0.0.0/24"),
		ip_network("192.0.2.0/24"),
		ip_network("192.88.99.0/24"),
		ip_network("192.168.0.0/16"),
		ip_network("198.18.0.0/15"),
		ip_network("198.51.100.0/24"),
		ip_network("203.0.113.0/24"),
		ip_network("224.0.0.0/4"),
		ip_network("240.0.0.0/4"),
	]

	def _is_public(net24) -> bool:
		for ex in EXCLUDED:
			if net24.subnet_of(ex):
				return False
		return True

	def _pick_seed(existing_seed: str | None) -> str:
		if existing_seed:
			return existing_seed
		# Fallback: pick a random public /24 as seed
		while True:
			addr = random.randint(0, 0xFFFFFFFF)
			addr = addr & 0xFFFFFF00  # align to /24
			net = ip_network(f"{IPv4Address(addr)}/24", strict=False)
			if _is_public(net):
				return str(net)

	def _offsets(start_with_up: bool):
		step = 1
		if start_with_up:
			yield 1
			yield -1
		else:
			yield -1
			yield 1
		step = 2
		while True:
			yield step
			yield -step
			step += 1

	inserted = 0
	BATCH = 1024
	async with get_db_session() as session:
		# Choose a random existing subnet as the seed
		seed_row = await session.execute(text("SELECT network::text FROM network_blocks WHERE status='COMPLETED' ORDER BY random() LIMIT 1"))
		seed_cidr = seed_row.scalar()
		#seed_cidr = None # random fallback
		seed_cidr = _pick_seed(seed_cidr)
		try:
			seed_net = ip_network(seed_cidr, strict=False)
		except Exception as e:
			print(f"Invalid seed subnet from DB '{seed_cidr}': {e}")
			return 2

		base_int = int(seed_net.network_address)
		start_with_up = bool(random.getrandbits(1))
		off_gen = _offsets(start_with_up)
		chunk: list[str] = []
		seen: set[str] = set()

		while inserted < count:
			try:
				off = next(off_gen)
			except StopIteration:
				break
			cand_int = base_int + (off * 256)
			if cand_int < 0 or cand_int > 0xFFFFFFFF:
				continue
			cand_net = ip_network(f"{IPv4Address(cand_int)}/24", strict=False)
			if not _is_public(cand_net):
				continue
			cidr = str(cand_net)
			if cidr in seen:
				continue
			seen.add(cidr)
			chunk.append(cidr)
			if len(chunk) >= BATCH:
				result = await session.execute(
					select(NetworkBlock.network).where(NetworkBlock.network.in_(chunk))
				)
				existing = {str(row[0]) for row in result.fetchall()}
				new_items = [c for c in chunk if c not in existing]
				needed = count - inserted
				to_add = new_items[:needed]
				if to_add:
					session.add_all([NetworkBlock(network=c, status="PENDING") for c in to_add])
					await session.commit()
					inserted += len(to_add)
					for c in to_add:
						print(f"Inserted network block '{c}'.")
				chunk.clear()

		# Final flush
		if inserted < count and chunk:
			result = await session.execute(
				select(NetworkBlock.network).where(NetworkBlock.network.in_(chunk))
			)
			existing = {str(row[0]) for row in result.fetchall()}
			new_items = [c for c in chunk if c not in existing]
			needed = count - inserted
			to_add = new_items[:needed]
			if to_add:
				session.add_all([NetworkBlock(network=c, status="PENDING") for c in to_add])
				await session.commit()
				inserted += len(to_add)
				for c in to_add:
					print(f"Inserted network block '{c}'.")

	print(f"Inserted {inserted} network blocks starting from seed {seed_cidr}.")
	return 0


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="Database CLI")
	subparsers = parser.add_subparsers(dest="command", required=True)

	add_nb = subparsers.add_parser(
		"add-network-block",
		help="Add a new network block to be crawled (e.g., 192.168.0.0/24)",
	)
	add_nb.add_argument("subnet", help="CIDR subnet string")

	add_n = subparsers.add_parser(
		"add-network-blocks",
		help="Add N unique public IPv4 /24 network blocks",
	)
	add_n.add_argument("-n", "--count", type=int, required=True, help="How many /24 blocks to add")

	return parser


def main() -> int:
	parser = build_parser()
	args = parser.parse_args()

	if args.command == "add-network-block":
		return asyncio.run(add_network_block(args.subnet))
	elif args.command == "add-network-blocks":
		return asyncio.run(add_network_blocks(args.count))

	print("Unknown command")
	return 1


if __name__ == "__main__":
	raise SystemExit(main())
