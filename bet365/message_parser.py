from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterator, List, Tuple

from prettytable import PrettyTable

from .utils import parse_odds, split_list_by_delimiter


@dataclass
class Bet365Section:
    """Represents a parsed section from Bet365 message format."""

    type: str
    properties: dict[str, str]

    def __init__(self, section_type: str, properties: dict[str, str]):
        self.type = section_type
        self.properties = properties

    def get_property(self, key: str, default: Any = None) -> str:
        """Get a property value with optional default."""
        return str(self.properties.get(key, default))

    def has_property(self, key: str) -> bool:
        """Check if section has a specific property."""
        return key in self.properties

    def __eq__(self, v):
        return (
            isinstance(v, Bet365Section)
            and v.type == self.type
            and v.properties == self.properties
        )


class Bet365MessageParser:
    """Parser for Bet365 message format data."""

    def __init__(self, sections: List[List[Bet365Section]]):
        self.sections = sections

    @staticmethod
    def parse_section_string(section_string: str) -> Bet365Section:
        """
        Parse a single section string into a Bet365Section object.

        Args:
            section_string: String in format "TYPE;key1=value1;key2=value2"

        Returns:
            Bet365Section object
        """
        parts = section_string.split(";")
        section_type = parts[0]
        properties = {}

        for part in parts[1:]:
            if part and "=" in part:
                key, value = part.split("=", 1)
                properties[key] = value

        return Bet365Section(section_type, properties)

    @staticmethod
    def parse_sections_list(sections_list: List[str]) -> List[Bet365Section]:
        """Parse a list of section strings into Bet365Section objects."""
        return [
            Bet365MessageParser.parse_section_string(section)
            for section in sections_list
            if section
        ]

    def find_sections(
        self, node_type: str, include_part_index: bool = False, **filters
    ) -> Iterator[Tuple[int, Bet365Section]]:
        """
        Find sections matching specified criteria across all section groups.

        Args:
            node_type: The section type to search for
            include_part_index: Whether to return part index along with section
            **filters: Property filters to apply

        Yields:
            Tuples of (index, section or part)
        """
        for section_group in self.sections:
            yield from self._find_in_section_group(
                section_group, node_type, include_part_index, **filters
            )

    @staticmethod
    def _find_in_section_group(
        section_group: List[Bet365Section],
        node_type: str,
        include_part_index: bool = False,
        **filters,
    ) -> Iterator[Tuple[int, Any]]:
        """Find matching sections within a single section group."""
        for idx, section in enumerate(section_group):
            if section.type == node_type and Bet365MessageParser._matches_filters(
                section, filters
            ):
                if include_part_index:
                    yield idx, section
                else:
                    yield idx, section_group

    @staticmethod
    def _matches_filters(section: Bet365Section, filters: Dict[str, Any]) -> bool:
        """Check if a section matches all specified filters."""
        for key, expected_value in filters.items():
            if key == "include_part_index":
                continue

            actual_value = section.get_property(key)

            if callable(expected_value):
                if not expected_value(key, actual_value):
                    return False
            elif actual_value != expected_value:
                return False

        return True


def get_parsers(data: str) -> List[Bet365MessageParser]:
    parsers = []
    parsed_sections = []
    for section_group in data.split("\b"):
        sections = section_group.split("|")
        parsed_sections.append(Bet365MessageParser.parse_sections_list(sections))

    for _section in parsed_sections:
        for section in split_list_by_delimiter(_section, Bet365Section("F", {})):
            if not section:
                continue
            parsers.append(Bet365MessageParser([section]))
    return parsers


def read_table(parser, idx, extra_properties=[]) -> Dict[str, Any]:
    assert parser.sections[0][idx + 1].type == "MA"
    result = {"title": parser.sections[0][idx].get_property("NA"), "data": []}

    idx += 1

    def get_key_name(idx) -> Tuple[str, int]:
        key_name = parser.sections[0][idx].get_property("NA")

        idx += 1
        if (
            key_name is None
            and parser.sections[0][idx].type == "CO"
            and parser.sections[0][idx].get_property("NA")
        ):
            key_name = parser.sections[0][idx].get_property("NA")
            idx += 1
        extra = {
            property: parser.sections[0][idx - 1].get_property(property)
            for property in extra_properties
            if parser.sections[0][idx - 1].get_property(property)
        }
        return key_name or "No row", idx, extra

    while idx < len(parser.sections[0]) and parser.sections[0][idx].type in [
        "MA",
        "CO",
    ]:
        name, idx, extra = get_key_name(idx)
        data = []
        while idx < len(parser.sections[0]) and parser.sections[0][idx].type == "PA":
            current_pa = parser.sections[0][idx]
            data.append(asdict(current_pa))
            idx += 1
        result["data"].append({"name": name, "values": data, "extra": extra})
    return result


def parse_bb(data: str) -> dict[str, Any]:
    results = {}
    for line in data.split("@"):
        splited = line.split(",")
        results[splited[0]] = {"PD": splited[1], "is_active": bool(int(splited[2]))}
    return results


def fix_data(table):
    data = table["data"]
    result = []
    for i in range(len(data[0]["values"])):
        row = [data[0]["values"][i]["properties"].get("FD", "")]
        for j in range(1, len(data)):
            row.append(
                f"{parse_odds(data[j]['values'][i]['properties'].get('OD', '')):0.2f}"
            )
        result.append(
            {
                "FD": data[0]["values"][i]["properties"].get("FD", ""),
                "ODS": [
                    data[j]["values"][i]["properties"].get("OD", "")
                    for j in range(1, len(data))
                ],
                "ODS_IDS": [
                    data[j]["values"][i]["properties"].get("ID", "")
                    for j in range(1, len(data))
                ],
                "other_properties": data[0]["values"][i]["properties"],
            }
        )
    return result


def pretty_print_table(table):
    data = table["data"]
    keys = [i["name"] for i in data]
    table = PrettyTable(keys)
    for i in range(len(data[0]["values"])):
        row = [data[0]["values"][i]["properties"].get("FD", "")]
        for j in range(1, len(data)):
            row.append(
                f"{parse_odds(data[j]['values'][i]['properties'].get('OD', '')):0.2f} {data[j]['values'][i]['properties'].get('OD', '')}"
            )
        table.add_row(row)

    print(table)
