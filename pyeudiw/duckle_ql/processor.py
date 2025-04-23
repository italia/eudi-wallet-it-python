from pyeudiw.duckle_ql.criteria import Criteria


class CriteriaProcessor:
    def __init__(self, raw_criteria: list[dict]):
        self.raw_criteria = raw_criteria

    def process(self) -> Criteria:
        """
        Transforms raw criteria definitions into a DCQLCriteria instance.
        For now, it just wraps them directly. In future, it could normalize paths, operators, etc.
        """
        normalized = []
        for criterion in self.raw_criteria:
            if not all(k in criterion for k in ("path", "operator", "value")):
                raise ValueError(f"Invalid criterion: {criterion}")
            normalized.append({
                "path": criterion["path"],
                "operator": criterion["operator"],
                "value": criterion["value"]
            })

        return Criteria(normalized)
