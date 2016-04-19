#include <list>

#include "service/singleton.h"

class CPCapCase : public singleton<CPCapCase>
{
public:
	int 
private:
	std::list<CPcapUnit*> m_CapUnitList;
};