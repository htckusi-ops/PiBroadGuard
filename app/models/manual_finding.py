from sqlalchemy import Column, Integer, String, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


class ManualFinding(Base):
    __tablename__ = "manual_findings"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False)
    category = Column(String)
    question_key = Column(String)
    answer_value = Column(String)
    comment = Column(Text)
    source = Column(String)

    assessment = relationship("Assessment", back_populates="manual_findings")
