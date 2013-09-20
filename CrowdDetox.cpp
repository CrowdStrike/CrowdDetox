/*!
    @file       CrowdDetox.cpp
    @author     Jason Geffner (jason@crowdstrike.com)
    @brief      CrowdDetox v1.0.1 Beta
   
    @details    The CrowdDetox plugin for Hex-Rays automatically removes junk
                code and variables from Hex-Rays function decompilations.

                See LICENSE file in top level directory for details.

    @copyright  CrowdStrike, Inc. Copyright (c) 2013.  All rights reserved. 
*/

//
// Disable warnings about:
// 1. Code in hexrays.hpp casting to bools
// 2. Deprecated code in typeinf.hpp (included by hexrays.hpp)
//
#pragma warning(push)
#pragma warning(disable: 4800 4996)
#include <hexrays.hpp>
#pragma warning(pop)

#define UNUSED(x) (void)(x)

//
// Hex-Rays API pointer
//
hexdsp_t* hexdsp = NULL;

//
// This global flag tracks whether or not this plugin has been initialized
//
bool g_fInitialized = false;

/*! 
    @brief Removes junk code and variables from the given function

    @param[in] pFunction The function from which to remove junk code and
                         variables
*/
void
Detox (
    cfunc_t* pFunction
    )
{
    lvars_t* pVariables;

    //
    // This structure is derived from ctree_visitor_t. It is used to find
    // legitimate ctree_t items and legitimate variables.
    //
    struct ida_local FIND_LEGIT_ITEMS_VISITOR : public ctree_visitor_t
    {
        private:

        //
        // This flag is used to ensure that afVariableIsLegit has been
        // initialized
        //
        bool fInitialized;

        //
        // This variable keeps track of the function being decompiled
        //
        cfunc_t* pFunction;

        //
        // This vector helps ensure we don't descend through items through
        // which we've already descended
        //
        qvector<citem_t*> vectorDescendantsMarkedLegit;

        //
        // This flag keeps track of the "mode" in which we're visiting ctree
        // items. By default, this flag is false. However, the code sets it to
        // true in order to mark all descendant ctree items and variables as
        // legitimate. Hex-Rays is single-threaded, so there are no thread-
        // safety issues.
        //
        bool fMarkingDescendantsLegit;

        /*! 
            @brief Determine if the given function call is legitimate (as
                   opposed to a trivial macro)

            @param[in] pExpression The expression containing the function call
            @return Returns true if the function call appears to be legitimate,
                    returns false otherwise
        */
        bool
        IsLegitimateCall (
            cexpr_t* pExpression
            )
        {
            cexpr_t* pCalledFunction;
            char szFunctionName[1024];

            //
            // These macros are from IDA's defs.h
            //
            char* aszNonLegitHelpers[] =
            {
                "__ROL__",
                "__ROL1__",
                "__ROL2__",
                "__ROL4__",
                "__ROL8__",
                "__ROR1__",
                "__ROR2__",
                "__ROR4__",
                "__ROR8__",
                "LOBYTE",
                "LOWORD",
                "LODWORD",
                "HIBYTE",
                "HIWORD",
                "HIDWORD",
                "BYTEn",
                "WORDn",
                "BYTE1",
                "BYTE2",
                "BYTE3",
                "BYTE4",
                "BYTE5",
                "BYTE6",
                "BYTE7",
                "BYTE8",
                "BYTE9",
                "BYTE10",
                "BYTE11",
                "BYTE12",
                "BYTE13",
                "BYTE14",
                "BYTE15",
                "WORD1",
                "WORD2",
                "WORD3",
                "WORD4",
                "WORD5",
                "WORD6",
                "WORD7",
                "SLOBYTE",
                "SLOWORD",
                "SLODWORD",
                "SHIBYTE",
                "SHIWORD",
                "SHIDWORD",
                "SBYTEn",
                "SWORDn",
                "SBYTE1",
                "SBYTE2",
                "SBYTE3",
                "SBYTE4",
                "SBYTE5",
                "SBYTE6",
                "SBYTE7",
                "SBYTE8",
                "SBYTE9",
                "SBYTE10",
                "SBYTE11",
                "SBYTE12",
                "SBYTE13",
                "SBYTE14",
                "SBYTE15",
                "SWORD1",
                "SWORD2",
                "SWORD3",
                "SWORD4",
                "SWORD5",
                "SWORD6",
                "SWORD7",
                "__CFSHL__",
                "__CFSHR__",
                "__CFADD__",
                "__CFSUB__",
                "__OFADD__",
                "__OFSUB__",
                "__RCL__",
                "__RCR__",
                "__MKCRCL__",
                "__MKCRCR__",
                "__SETP__",
                "__MKCSHL__",
                "__MKCSHR__",
                "__SETS__",
                "__ROR__"
            };

            //
            // Ensure that the input expression is a call
            //
            if (pExpression->op != cot_call)
            {
                return false;
            }

            //
            // Get a pointer to the called function
            //
            pCalledFunction = pExpression->x;

            //
            // If the called function isn't a built-in "helper" (IDA macro),
            // assume it's a call to a legitimate function
            //
            if (pCalledFunction->op != cot_helper)
            {
                return true;
            }

            //
            // Get the name of the called "helper" function/macro
            //
            if (0 == pCalledFunction->print1(
                szFunctionName,
                _countof(szFunctionName) - 1,
                NULL))
            {
                return false;
            }
            tag_remove(
                szFunctionName,
                szFunctionName,
                _countof(szFunctionName) - 1);

            //
            // If the helper function is one of the macros from defs.h, it's
            // not *necessarily* legitimate (though if one of the arguments to
            // the function is legitimate, then the expression will get marked
            // as legitimate anyway)
            //
            for (int i = 0; i < _countof(aszNonLegitHelpers); i++)
            {
                if (0 == strcmp(szFunctionName, aszNonLegitHelpers[i]))
                {
                    return false;
                }
            }

            //
            // Otherwise, if the helper function is something like
            // "__readfsdword", then it's probably legitimate
            //
            return true;
        }

        /*!
            @brief This function, called by Hex-Rays when the ctree visitor
                   visits an expresison item, is a stub for visit_item()

            @param[in] pExpression The visited expression item
            @return Returns 0 to continue the traversal, returns 1 to stop
                    the traversal
        */
        int
        idaapi
        visit_expr (
            cexpr_t* pExpression
            )
        {
            return visit_item(
                pExpression);
        }

        /*!
            @brief This function, called by Hex-Rays when the ctree visitor
                   visits a statement item, is a stub for visit_item()

            @param[in] pExpression The visited statement item
            @return Returns 0 to continue the traversal, returns 1 to stop
                    the traversal
        */
        int
        idaapi
        visit_insn (
            cinsn_t* pInstruction
            )
        {
            return visit_item(
                pInstruction);
        }

        /*! 
            @brief This function determines if a ctree item is legitimate; it
                   marks variables legitimate via the afVariableIsLegit array
                   and saves legitimate items in the vectorLegitItems vector

            @param[in] pItem The visited ctree item
            @return Returns 0 to continue the traversal, returns 1 to stop
                    the traversal
        */
        int
        visit_item (
            citem_t* pItem
            )
        {
            cexpr_t* pExpression;
            char szType[16];

            //
            // Ensure that we're initialized
            //
            if (!fInitialized)
            {
                if (!Initialize())
                {
                    return 1;
                }
            }

            //
            // If we're traversing the graph solely to mark descendants as
            // legitimate...
            //
            if (fMarkingDescendantsLegit)
            {
                //
                // Don't descend through items through which we've already
                //   descended
                //
                if (vectorDescendantsMarkedLegit.has(pItem))
                {
                    return 0;
                }

                //
                // If this is a variable, mark the variable legitimate
                //
                if (pItem->op == cot_var)
                {
                    afVariableIsLegit[((cexpr_t*)pItem)->v.idx] = true;
                }

                //
                // Mark the item itself legitimate
                //
                if (!vectorLegitItems.has(pItem))
                {
                    vectorLegitItems.push_back(
                        pItem);
                    fNewLegitItemFound = true;
                }

                //
                // Remember that we've now descended through this item
                //
                vectorDescendantsMarkedLegit.push_back(
                    pItem);

                //
                // Continue marking other descendant items as legitimate
                //
                return 0;
            }

            //
            // If this item was already marked as legititmate...
            //
            if (vectorLegitItems.has(pItem))
            {
                //
                // If we have a legitimate item that's an if/for/while/do/
                // return statement then mark the expression part of that node
                // (for example, the "x" in "if(x)") as legitimate as well
                //
                pExpression = NULL;
                switch (pItem->op)
                {
                case cit_if:
                    pExpression = &((cinsn_t*)pItem)->cif->expr; break;
                case cit_for:
                    pExpression = &((cinsn_t*)pItem)->cfor->expr; break;
                case cit_while:
                    pExpression = &((cinsn_t*)pItem)->cwhile->expr; break;
                case cit_do:
                    pExpression = &((cinsn_t*)pItem)->cdo->expr; break;
                case cit_return:
                    pExpression = &((cinsn_t*)pItem)->creturn->expr; break;
                default:
                    break;
                }
                if (pExpression == NULL)
                {
                    return 0;
                }

                //
                // If the expression hasn't already been marked as legitimate
                // then mark it so and mark all of its descendants as
                // legitimate as well
                //
                if (!vectorDescendantsMarkedLegit.has(pExpression))
                {
                    //
                    // Mark all items under this expression/call as legitimate
                    //
                    fMarkingDescendantsLegit = true;
                    apply_to(
                        pExpression,
                        NULL);
                    fMarkingDescendantsLegit = false;

                    //
                    // cit_for statements require us to also process the
                    // for-loop initialization and step expressions
                    //
                    if (pItem->op == cit_for)
                    {
                        //
                        // Process the for-loop's initialization expression
                        //
                        pExpression = &((cinsn_t*)pItem)->cfor->init;
                        if (!vectorDescendantsMarkedLegit.has(pExpression))
                        {
                            //
                            // Mark all items under this expression as legit
                            //
                            fMarkingDescendantsLegit = true;
                            apply_to(
                                pExpression,
                                NULL);
                            fMarkingDescendantsLegit = false;
                        }

                        //
                        // Process the for-loop's step expression
                        //
                        pExpression = &((cinsn_t*)pItem)->cfor->step;
                        if (!vectorDescendantsMarkedLegit.has(pExpression))
                        {
                            //
                            // Mark all items under this expression as legit
                            //
                            fMarkingDescendantsLegit = true;
                            apply_to(
                                pExpression,
                                NULL);
                            fMarkingDescendantsLegit = false;
                        }
                    }
                }

                return 0;
            }

            //
            // If this item is a legitimate variable and/or a CPPEH_RECORD
            // variable, or a function, global variable, legit macro, goto,
            // break, continue, return, or asm-statement then mark the ancestor
            // expressions as legitimate
            //
            if (pItem->op == cot_var)
            {
                if (!afVariableIsLegit[((cexpr_t*)pItem)->v.idx])
                {
                    if (T_NORMAL != print_type_to_one_line(
                        szType,
                        _countof(szType),
                        idati,
                        ((cexpr_t*)pItem)->type.u_str()))
                    {
                        return 0;
                    }
                    if (0 != strcmp(szType, "CPPEH_RECORD"))
                    {
                        return 0;
                    }
                }
            }
            else if (!((pItem->op == cot_obj) ||
                ((pItem->op == cot_call) &&
                    IsLegitimateCall((cexpr_t*)pItem)) ||
                (pItem->op == cit_goto) ||
                (pItem->op == cit_break) ||
                (pItem->op == cit_continue) ||
                (pItem->op == cit_return)) ||
                (pItem->op == cit_asm))
            {
                return 0;
            }

            //
            // Iterate through all ancestors (assumes that the decompilation
            // graph is a tree and that no item has more than one parent)
            //
            for(citem_t* pCurrentItem = pItem;
                pCurrentItem != NULL;
                pCurrentItem = pFunction->body.find_parent_of(pCurrentItem))
            {
                if (!vectorLegitItems.has(pCurrentItem))
                {
                    vectorLegitItems.push_back(
                        pCurrentItem);
                    fNewLegitItemFound = true;
                }

                if ((pCurrentItem->op == cit_expr) ||
                    ((pCurrentItem->op == cot_call) &&
                        IsLegitimateCall((cexpr_t*)pCurrentItem)) ||
                    (pCurrentItem->op == cit_return))
                {
                    //
                    // This is a cit_expr statement node or cot_call
                    // expression
                    //

                    if (!vectorDescendantsMarkedLegit.has(pCurrentItem))
                    {
                        //
                        // Mark all items under this expression/call as legit
                        //
                        fMarkingDescendantsLegit = true;
                        apply_to(
                            pCurrentItem,
                            NULL);
                        fMarkingDescendantsLegit = false;
                    }
                }
            }

            return 0;
        }


        public:

        //
        // This flag keeps track of whether or not new legitimate ctree items
        // were found during the ctree traversal
        //
        bool fNewLegitItemFound;

        //
        // This vector is a list of all legitimate ctree items
        //
        qvector<citem_t*> vectorLegitItems;

        //
        // This flag array (indexed to match the order of indeces in the
        // function's lvars_t vector) keeps track of whether each variable is
        // legitimate or not
        //
        bool* afVariableIsLegit;

        /*! 
            @brief Allocate and initialize the afVariableIsLegit array

            @param[in] pItem The visited ctree item
            @return Returns 0 to continue the traversal, returns 1 to stop
                    the traversal
        */
        bool
        Initialize (
            void
            )
        {
            lvars_t* pVariables;

            //
            // Allocate the afVariableIsLegit array
            //
            pVariables = pFunction->get_lvars();
            afVariableIsLegit = (bool*)malloc(
                pVariables->size());
            if (afVariableIsLegit == NULL)
            {
                msg(
                    "CrowdDetox error: Cannot allocate %d bytes.\n",
                    pVariables->size() * sizeof(bool));
                return false;
            }

            //
            // Initialize the afVariableIsLegit array based on function
            // arguments
            //
            for (size_t i = 0; i < pVariables->size(); i++)
            {
                afVariableIsLegit[i] = pVariables->at(i).is_arg_var();
            }

            fInitialized = true;

            return true;
        }

        //
        // FIND_LEGIT_ITEMS_VISITOR constructor
        //
        FIND_LEGIT_ITEMS_VISITOR(cfunc_t* _pFunction):
            ctree_visitor_t(CV_PARENTS),
            fInitialized(false),
            pFunction(_pFunction),
            afVariableIsLegit(NULL),
            fNewLegitItemFound(false),
            fMarkingDescendantsLegit(false)
        {
            //
            // Do nothing
            //
        }

        //
        // FIND_LEGIT_ITEMS_VISITOR destructor
        //
        ~FIND_LEGIT_ITEMS_VISITOR()
        {
            //
            // Free the afVariableIsLegit array
            //
            if (afVariableIsLegit != NULL)
            {
                free(
                    afVariableIsLegit);
                afVariableIsLegit = NULL;
            }
        }
    };

    //
    // Keep traversing the function's ctree until no new legitimate items are
    // found
    //
    FIND_LEGIT_ITEMS_VISITOR fliv(pFunction);
    do
    {
        fliv.fNewLegitItemFound = false;
        fliv.apply_to(
            &pFunction->body,
            NULL);
    } while (fliv.fNewLegitItemFound);


    //
    // This structure is derived from ctree_visitor_t. It is used to prune
    // junk ctree_t items from the decompilation graph.
    //
    struct ida_local PRUNE_ITEMS_VISITOR : public ctree_visitor_t
    {
        private:

        //
        // This vector is a list of all previously-found legitimate ctree items
        //
        qvector<citem_t*>* pVectorLegitItems;

        //
        // This variable keeps track of the function being decompiled
        //
        cfunc_t* pFunction;

        //
        // The modes in which the decompilation tree will be traversed
        //
        enum VisitingMode
        {
            Pruning,
            CleaningUpGotoLabels,
            ChangingGotos,
            FindingChildrenOfParent
        };
        VisitingMode visitingMode;

        //
        // Used in FindingChildrenOfParent visiting mode. Parent currently
        // being analyzed.
        //
        citem_t* pCurrentParent;

        //
        // Used in FindingChildrenOfParent visiting mode. This vector tracks
        // children of the currently analyzed parent block.
        //
        qvector<citem_t*> vectorChildrenOfParentBlock;

        //
        // Used in ChangingGotos visiting mode. Stores original goto
        // destination label number.
        //
        int nOldLabelNumber;

        //
        // Used in ChangingGotos visiting mode. Stores new goto destination
        // label number. If -1, change gotos to return.
        //
        int nNewLabelNumber;

        //
        // If this item and all of its descendants contain no goto-labels,
        // this is false (no cleaning up done). If a goto label was cleaned up,
        // this is true.
        bool fGotoCleaned;

        /*!
            @brief This function, called by Hex-Rays when the ctree visitor
                   visits an expresison item, is a stub for visit_item()

            @param[in] pExpression The visited expression item
            @return Returns 0 to continue the traversal, returns 1 to stop
                    the traversal
        */
        int
        idaapi
        visit_expr (
            cexpr_t* pExpression
            )
        {
            return visit_item(
                pExpression);
        }

        /*!
            @brief This function, called by Hex-Rays when the ctree visitor
                   visits a statement item, is a stub for visit_item()

            @param[in] pExpression The visited statement item
            @return Returns 0 to continue the traversal, returns 1 to stop
                    the traversal
        */
        int
        idaapi
        visit_insn (
            cinsn_t* pInstruction
            )
        {
            return visit_item(
                pInstruction);
        }

        /*! 
            @brief This function prunes junk items from the decompilation graph

            @param[in] pItem The visited ctree item
            @return Returns 0 to continue the traversal, returns 1 to stop
                    the traversal
        */
        int
        visit_item (
            citem_t* pItem
            )
        {
            cblock_t* pBlock;
            citem_t* pParent;
            citem_t* pNewDestination;

            //
            // If we're in the (default) Pruning mode...
            //
            if (visitingMode == Pruning)
            {
                //
                // Erase all empty items from cit_block items
                //
                if (pItem->op == cit_block)
                {
                    pBlock = ((cinsn_t*)pItem)->cblock;
                    for (
                        cblock_t::iterator pIterator = pBlock->begin();
                        pIterator != pBlock->end();
                        pIterator++)
                    {
                        if ((pIterator->op == cit_empty) ||
                            (pIterator->op == cot_empty))
                        {
                            pBlock->erase(
                                pIterator);
                            fPruned = true;
                            return 1;
                        }
                    }
                    return 0;
                }

                //
                // Don't cleanup cit_break, cit_continue, cit_goto, cit_empty,
                // cot_empty, cit_asm, or cit_return items
                //
                if ((pItem->op == cit_break) ||
                    (pItem->op == cit_continue) ||
                    (pItem->op == cit_goto) ||
                    (pItem->op == cit_empty) ||
                    (pItem->op == cot_empty) ||
                    (pItem->op == cit_asm) ||
                    (pItem->op == cit_return))
                {
                    //
                    // Don't cleanup descendants of these items, either
                    //
                    prune_now();

                    return 0;
                }

                //
                // Cleanup everything else unless it's marked as legitimate
                //
                if (pVectorLegitItems->has(pItem))
                {
                    return 0;
                }

                //
                // Only cleanup statements, not expressions
                //
                if (pItem->is_expr())
                {
                    return 0;
                }

                //
                // Keep cleaning up goto labels under this item until no labels
                // remain
                //
                visitingMode = CleaningUpGotoLabels;
                fGotoCleaned = true;
                while (fGotoCleaned)
                {
                    fGotoCleaned = false;
                    apply_to(
                        pItem,
                        NULL);
                }
                visitingMode = Pruning;

                //
                // Execute the actual cleanup() call
                //
                ((cinsn_t*)pItem)->cleanup();

                fPruned = true;
                return 1;
            }

            //
            // If we're in CleaningUpGotoLabels mode...
            //
            else if (visitingMode == CleaningUpGotoLabels)
            {
                //
                // Keep searching this tree branch until we find a goto label
                //
                if (pItem->label_num == -1)
                {
                    return 0;
                }

                //
                // We found an item with a goto label, so save its old label
                // number
                //
                nOldLabelNumber = pItem->label_num;

                //
                // Find a new place to assign this label
                //
                pParent = pItem;
                pNewDestination = NULL;
                while (pNewDestination == NULL)
                {
                    while (NULL != (pParent = pFunction->body.find_parent_of(pParent)))
                    {
                        if (pParent->op == cit_block)
                        {
                            break;
                        }
                    }

                    if (pParent == NULL)
                    {
                        //
                        // We couldn't find any parent block, which means we
                        // can't move the goto label. Instead, change the gotos
                        // that point to this label into returns.
                        //

                        //
                        // Change gotos that jump to nOldLabelNumber to instead
                        // be returns
                        //
                        nNewLabelNumber = -1;
                        visitingMode = ChangingGotos;
                        apply_to(
                            &pFunction->body,
                            NULL);
                    
                        fGotoCleaned = true;
                        return 1;
                    }

                    //
                    // The parent block was found. See if there are any
                    // children of that parent block whose EA is greater than
                    // that of the current label's item.
                    //
                    pCurrentParent = pParent;
                    vectorChildrenOfParentBlock.clear();
                    visitingMode = FindingChildrenOfParent;
                    apply_to(
                        pParent,
                        NULL);
                    visitingMode = CleaningUpGotoLabels;

                    for (size_t i = 0;
                        i < vectorChildrenOfParentBlock.size();
                        i++)
                    {
                        if (!(vectorChildrenOfParentBlock[i]->ea > pItem->ea))
                        {
                            continue;
                        }

                        if ((pNewDestination == NULL) ||
                            (vectorChildrenOfParentBlock[i]->ea <
                            pNewDestination->ea))
                        {
                            pNewDestination = vectorChildrenOfParentBlock[i];
                        }
                    }
                }

                //
                // We now have a pNewDestination for our label
                //

                //
                // If the new destination already has a label number...
                //
                if (pNewDestination->label_num != -1)
                {
                    //
                    // Update all goto items in the graph that originally
                    // pointed to the old label to now point to
                    // pNewDestination's label
                    //
                    nNewLabelNumber = pNewDestination->label_num;
                    visitingMode = ChangingGotos;
                    apply_to(
                        &pFunction->body,
                        NULL);
                    
                    fGotoCleaned = true;
                    return 1;
                }

                //
                // Otherwise, just move the label
                //
                pNewDestination->label_num = pItem->label_num;
                pItem->label_num = -1;

                fGotoCleaned = true;

                return 1;
            }

            //
            // If we're in FindingChildrenOfParent mode...
            //
            else if (visitingMode == FindingChildrenOfParent)
            {
                //
                // If the item is a child of the current parent, add it to the
                // vectorChildrenOfParentBlock vector
                //
                if (parents.back() == pCurrentParent)
                {
                    vectorChildrenOfParentBlock.push_back(pItem);
                }

                return 0;
            }

            //
            // If we're in the ChaningGotos mode...
            //
            else if (visitingMode == ChangingGotos)
            {
                //
                // Change cit_goto items to either point to a new goto label or
                // to be a cit_return instead.
                //

                if (!((pItem->op == cit_goto) &&
                    (((cinsn_t*)pItem)->cgoto->label_num == nOldLabelNumber)))
                {
                    return 0;
                }

                if (nNewLabelNumber != -1)
                {
                    //
                    // Change the destination label of the goto
                    //
                    ((cinsn_t*)pItem)->cgoto->label_num = nNewLabelNumber;
                    return 0;
                }

                //
                // Change the goto to a return
                //
                cinsn_t* pRet = new cinsn_t();
                pRet->ea = pItem->ea;
                pRet->op = cit_return;
                pRet->label_num = pItem->label_num;
                pRet->index = pItem->index;
                pRet->creturn = new creturn_t();

                ((cinsn_t*)pItem)->replace_by(pRet);
                ((cinsn_t*)pItem)->cleanup();

                return 0;
            }

            return 1;
        }


        public:

        //
        // This flag keeps track of whether or not any ctree items were pruned
        // during the ctree traversal
        //
        bool fPruned;

        //
        // PRUNE_ITEMS_VISITOR constructor
        //
        PRUNE_ITEMS_VISITOR(cfunc_t* _pFunction, qvector<citem_t*>* _pVectorLegitItems):
            ctree_visitor_t(CV_PARENTS),
            pFunction(_pFunction),
            pVectorLegitItems(_pVectorLegitItems),
            visitingMode(Pruning),
            fGotoCleaned(false),
            fPruned(false),
            nOldLabelNumber(-1),
            nNewLabelNumber(-1)
        {
        }
    };

    //
    // Keep traversing the function's ctree until there are no items left to
    // prune
    //
    PRUNE_ITEMS_VISITOR piv(pFunction, &fliv.vectorLegitItems);
    do
    {
        piv.fPruned = false;
        piv.apply_to(
            &pFunction->body,
            NULL);
    } while (piv.fPruned);


    //
    // Clear the CVAR_USED flag from all variables not found to be legitimate
    //
    pVariables = pFunction->get_lvars();
    for (size_t i = 0; i < pVariables->size(); i++)
    {
        if (!fliv.afVariableIsLegit[i])
        {
            pVariables->at(i).clear_used();
        }
    }
}

/*! 
    @brief Hex-Rays callback function, where CrowdDetox hooks into
           decompilation process

    @param[in] pUserData Reserved
    @param[in] event Hex-Rays decompiler event code
    @param[in] va Additional arguments
    @return Always returns 0
*/
int
idaapi
HexRaysEventCallback (
    void* pUserData,
    hexrays_event_t event,
    va_list va
    )
{
    UNUSED(pUserData);

    cfunc_t* pFunction;
    ctree_maturity_t maturity;

    //
    // If the event wasn't a change in the maturity level of the decompilation
    // then disregard the event
    //
    if (event != hxe_maturity)
    {
        return 0;
    }

    //
    // Get the new maturity level of the decompilation
    //
    pFunction = va_arg(
        va,
        cfunc_t*);
    maturity = va_argi(
        va,
        ctree_maturity_t);

    //
    // If Hex-Rays has not yet finished its decompilation then disregard the
    // event
    //
    if (maturity != CMAT_FINAL)
    {
        return 0;
    }

    //
    // Hex-Rays has finalized its decompilation of the function, so now remove
    // the junk code and variables from the decompiled function
    //
    Detox(
        pFunction);

    return 0;
}

/*! 
    @brief This initialization function runs when the plugin is first loaded
    @details Installs the HexRaysEventCallback callback and initializes the
             checkbox icons
 
    @return Returns PLUGIN_KEEP on success, returns PLUGIN_SKIP on error
*/
int
idaapi
PLUGIN_init (
    void
    )
{
    //
    // Initialize the plugin for Hex-Rays
    //
    if (!init_hexrays_plugin())
    {
        //
        // Don't load CrowdDetox if Hex-Rays is not installed
        //
        g_fInitialized = false;
        return PLUGIN_SKIP;
    }

    msg(
        "CrowdDetox plugin loaded; to detox a function's decompilation, press "
        "'Shift-F5'.\n"
        "If a function's return value is not used by its caller, you should "
        "manually set the function's prototype to specify that it returns "
        "'void' in order to assist the CrowdDetox plugin.\n");

    g_fInitialized = true;

    return PLUGIN_KEEP;
}

/*! 
    @brief This is the plugin termination function
*/
void
idaapi
PLUGIN_term (
    void
    )
{
    if (g_fInitialized)
    {
        term_hexrays_plugin();
    }
}

/*! 
    @brief This function runs when a user presses Shift-F5
    @details Runs Detox() on the current function
 
    @param[in] arg Reserved
*/
void
idaapi
PLUGIN_run (
    int arg
    )
{
    UNUSED(arg);

    //
    // Install the Hex-Rays event callback function
    //
    if (!install_hexrays_callback(
        HexRaysEventCallback,
        NULL))
    {
        msg(
            "Failed to install CrowdDetox Hex-Rays callback.\n");
        return;
    }

    //
    // Open the Hex-Rays pseudocode window, or refresh the current pseudocode
    // window if it's already open
    //
    open_pseudocode(
        get_screen_ea(),
        0);

    //
    // Uninstall the Hex-Rays event callback function
    //
    remove_hexrays_callback(
        HexRaysEventCallback,
        NULL);
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,          // IDA Plugin Interface version number
    NULL,                           // Plugin flags
    PLUGIN_init,                    // Initialization function
    PLUGIN_term,                    // Termination function
    PLUGIN_run,                     // Plugin invocation function
    "",                             // Long comment about the plugin
    "The CrowdDetox plugin "        // Multiline help about the plugin
        "automatically removes junk code and variables from Hex-Rays function "
        "decompilations.",
    "CrowdDetox",                   // The preferred short name of the plugin
    "Shift-F5"                      // The preferred hotkey to run the plugin
};
