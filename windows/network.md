# مراجعة اتصالات الشبكة

ستحتاج برمجيات التجسس في النهاية إلى نقل البيانات التي تم جمعها (مثل لقطات الشاشة وكلمات المرور وضغطات المفاتيح وما إلى ذلك) إلى موقع بعيد وهو [خادم القيادة والتحكم](https://www.crowdstrike.com/cybersecurity-101/cyberattacks/command-and-control/). وبالرغم من أنه من غير الممكن أن تتمكن من التنبؤ بموعد حدوث عمليات الإرسال هذه، من الممكن أن بعض برمجيات التجسس تجري اتصالًا دائم مع الخادم أو تتصل به بشكل متكرر بما يكفي لكشفها.

من أجل التحقق من الاتصالات الجارية يمكنك على سبيل المثال تسجيل حركة مرور الشبكة بأكملها باستخدام [Wireshark](https://www.wireshark.org/) وفحص النتائج المخزنة لاحقًا، ولكن النهج الأكثر الأفضل هو استخدام الأدوات التي لا تراقب نشاط الشبكة فحسب بل يمكنها أيضًا ربطها بالعمليات قيد التشغيل. بشكل عام يجب أن تبحث عن عمليات غير عادية تتصل بعناوين بروتوكول إنترنت مشبوهة.

وإحدى الأدوات الشائعة للقيام بذلك هي [تي سي بي فيو (TCPView](https://technet.microsoft.com/en-us/sysinternals/tcpview.aspx)) أيضًا من سيسينترنال سويت (Sysinternals Suite) من مايكروسوفت.

تُعدّ هذه الأداة سهلة للغاية فهي تسرد جميع اتصالات الشبكة القائمة وتوفر معلومات حول عملية المصدر والوجهة، ومن المحتمل أن تتفاجأ بملاحظة كمية اتصالات الشبكة النشطة حتى في الأنظمة التي تبدو خاملة. غالبًا ما سترى نشاط شبكة من العمليات الخلفية على سبيل المثال لخدمات مايكروسوفت وجوجل كروم وأدوبي ريدر (Adobe Reader) وسكايب (Skype) وما إلى ذلك.

توجد أداة أخرى يمكننا استخدامها لمراقبة اتصالات الشبكة النشطة وهي كراود إنسبكت التي عرضناها في القسم السابق حول [فحص العمليات قيد التشغيل](https://pellaeon.gitbook.io/mobile-forensics/windows/processes). تشابه المعلومات التي تقدمها أداة كراود إنسبكت كثيرًا تلك التي تقدمها تي سي بي فيو.

![](https://pellaeon.gitbook.io/~gitbook/image?url=https%3A%2F%2F3800278430-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F0nYvTpYLyJhfHy1skKdP%252Fuploads%252Fgit-blob-0df9444d13cda112b776049ff601600ce78e8fe3%252Fcrowdinspect_injection.png%3Falt%3Dmedia&width=768&dpr=4&quality=100&sign=ccd4f3c9&sv=1)

على سبيل المثال، في لقطة الشاشة أعلاه يمكننا رؤية عملية `iexplore.exe` قيد التشغيل والتي تظهر عليها علامة _محقونة،_ ويبدو أيضًا أنها تحاول بنشاط الاتصال ببروتوكول إنترنت بعيد على العنوان `216.6.0.28`. نظرًا لعدم وجود نافذة ظاهرة لبرنامج إنترنت اكسبلورر تعمل على النظام، يثير الشك بالتأكيد مشاهدة اتصالات شبكة نشطة منه، ويظهر تي سي بي فيو كما يلي على النظام المصاب ذاته:

![](https://pellaeon.gitbook.io/~gitbook/image?url=https%3A%2F%2F3800278430-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F0nYvTpYLyJhfHy1skKdP%252Fuploads%252Fgit-blob-4a422efefc0fa08dd19d89ef97b6d556200cbc98%252Ftcpview_infected.png%3Falt%3Dmedia&width=768&dpr=4&quality=100&sign=ec4f4c02&sv=1)

(ملاحظة: تعرض هذه الأدوات محاولات الاتصال بالمواقع البعيدة حتى لو كان الكمبيوتر في الوقت الحالي غير متصل بالإنترنت).

عندما تشك في وجود اتصال نشط يمكنك (ويفضل أن تقوم بذلك من جهاز كمبيوتر منفصل) البحث عن عنوان بروتوكول الإنترنت ومحاولة تحديد لمن يعود وما إذا كان معروفًا أنه سليم أم ضار باستخدام أدوات عبر الإنترنت مثل [Central Ops](https://centralops.net/co/) أو [ipinfo](https://ipinfo.io/). على سبيل المثال، ينتج عن بحث WHOIS بسيط يتعلق بعنوان بروتوكول الإنترنت هذا:

```
NetRange:       216.6.0.0 - 216.6.1.255  
CIDR:           216.6.0.0/23  
NetName:        SYRIAN-5  
NetHandle:      NET-216-6-0-0-2  
Parent:         TATAC-ARIN-9 (NET-216-6-0-0-1)  
NetType:        Reassigned  
OriginAS:  
Organization:   STE (Syrian Telecommunications Establishment) (SSTE)  
RegDate:        2005-07-21  
Updated:        2005-07-21  
Comment:        Fax-no-963 11 3739765  
Ref:            https://rdap.arin.net/registry/ip/216.6.0.0

OrgName:        STE (Syrian Telecommunications Establishment)  
OrgId:          SSTE  
Address:        Fayz Mansour St  
Address:        STE Building  
City:           Damascus  
StateProv:  
PostalCode:  
Country:        SY  
RegDate:        2005-07-21  
Updated:        2011-09-24  
Ref:            https://rdap.arin.net/registry/entity/SSTE
```
يشير هذا إلى أن برنامج `iexplore.exe` المحقون كان يحاول بشكل مريب للغاية الاتصال بعنوان بروتوكول إنترنت موجود في سوريا. في الواقع ولغرض العرض التوضيحي استخدمنا نسخة قديمة من فيروس حصان طروادة الذي يتيح الوصول عن بُعد المسمى DarkComet الذي عثر على أنه يُستخدم في سوريا في عام  2011 تقريبا,

وحتى بحث بسيط عن عنوان بروتوكول الإنترنت عبر محرك البحث المفضل لديك قد يكشف عن معلومات مفيدة. بالإضافة إلى ذلك، قد ترغب في التفكير في استخدام خدمات أبحاث التهديدات مثل [ريسك آي كيو (RiskIQ)](https://community.riskiq.com/) أو [ثريت ماينر (ThreatMiner)](https://www.threatminer.org/) لمعرفة ما إذا كان لديهم أي معلومات عن عناوين بروتوكول الإنترنت أو أسماء النطاقات التي تصادفها.